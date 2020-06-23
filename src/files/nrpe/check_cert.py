#!/usr/bin/python3
# Copyright 2022 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
from datetime import datetime, timedelta
import nagios_plugin3
from OpenSSL import crypto


class Certificate:
    DATE_FMT = '%Y%m%d%H%M%SZ'

    def __init__(self, fp_obj):
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, fp_obj.read())

    @property
    def end_date(self):
        """Read the expiration date from the cert."""
        date = self.cert.get_notAfter().decode('utf-8')
        return datetime.strptime(date, self.DATE_FMT)


def run_check(args):
    """
    Run the nrpe check on a certificate.

    :params args: parse args namespace
    """
    file_name = args.certificate.name
    try:
        cert = Certificate(args.certificate)
    except crypto.Error:
        raise nagios_plugin3.UnknownError(
            "UNKNOWN: Couldn't open certificate file %s" % file_name
        )

    ages_str = args.ages.split(",")
    if len(ages_str) < 1 or len(ages_str) > 2:
        raise nagios_plugin3.UnknownError(
            "UNKNOWN: Invalid check option -C %s" % ages_str
        )

    ages = []
    for each in ages_str:
        ages.append(int(each))

    now = datetime.now()
    for idx, days in enumerate(ages):
        if (now + timedelta(days=days)) > cert.end_date:
            days_left = (cert.end_date - now).days
            ends = cert.end_date.isoformat(' ')
            msg = "Certificate expires in %s day(s) (%s)" % (days_left, ends)
            if idx == 0:
                raise nagios_plugin3.CriticalError("CRITICAL: " + msg)
            elif idx == 1:
                raise nagios_plugin3.WarnError("WARNING: " + msg)
    print("OK: Certificate is valid")


def main():
    """Parse arguments from stdin, and run check."""
    parser = argparse.ArgumentParser(description="Validate Certificate files")
    parser.add_argument('certificate', type=argparse.FileType('r'),
                        help="Certificate PEM File")
    parser.add_argument('-C', dest='ages', help='crit_age[,warn_age]',
                        default='14')
    args = parser.parse_args()
    run_check(args)


if __name__ == '__main__':
    nagios_plugin3.try_check(main)
