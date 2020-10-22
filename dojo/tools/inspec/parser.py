import json
from dojo.models import Finding


class InspecScannerParser(object):
    def __init__(self, filename, test):
        tree = filename.read()
        try:
            data = json.loads(str(tree, 'utf-8'))
        except:
            data = json.loads(tree)

        platform_name = data['platform']['name']
        platform_rel = data['platform']['release']

        self.items = list()

        # A Profile is analogous to a Test, but for the purposes
        # of the import, we'll just focus on the controls
        for profile in data['profiles']:
            for attribute in profile['attributes']:
                pass
            for support in profile['supports']:
                pass
            for group in profile['groups']:
                pass
            for control in profile['controls']:
                title = control['title']
                description = control['desc']
                sev = control['impact']
                #
                # An approach to handling severity. If any
                # test fails, then severity is the translated
                # value of impact
                #
                passed = True
                repro_steps = ''
                for result in control['results']:
                    if result['status'] == 'failed':
                        passed = False
                        repro_steps = result['code_desc'] + \
                            '\nFailed with message:' + result['message']

                waiver_data = control['waiver_data']
                cve = None
                cwe = None
                references = ''
                if control['refs']:
                    for ref in control['refs']:
                        if ref['CVE']:
                            cve = ref['CVE']
                        if ref['CWE']:
                            cve = ref['CWE']
                        for key in ref:
                            references += str(key) + ":" + str(ref[key]) + "\n"

                if waiver_data:
                    # Control was waived
                    description += "NOTE:\nA Waiver has been set for this control\n" + \
                        "Waiver Information:\n" + \
                        "Expiration: " + waiver_data['expiration_date'] + '\n' + \
                        "Justification: " + waiver_data['justification'] + '\n' + \
                        "Message: " + waiver_data['message']
                if passed:
                    severity = 'Info'
                else:
                    if sev > .9:
                        severity = 'Critical'
                    elif sev > .7:
                        severity = 'High'
                    elif sev > .5:
                        severity = 'Medium'
                    elif sev > .1:
                        severity = 'Low'
                    else:
                        severity = 'Info'
                    impact = str(control['impact'])

                    ln = control["source_location"]['line']
                    source = control['source_location']['ref']

                    # estimate a scale for severity
                    finding = Finding(title=title,
                                      test=test,
                                      description=description,
                                      severity=severity,
                                      numerical_severity=Finding.get_numerical_severity(
                                          severity),
                                      impact=impact,
                                      steps_to_reproduce=repro_steps,
                                      file_path=source,
                                      line=ln,
                                      unique_id_from_tool=control['id'],
                                      cwe=cwe,
                                      cve=cve)
                    self.items.append(finding)
        # statistics
        version = data['version']
