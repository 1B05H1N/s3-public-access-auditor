import unittest

import s3_audit as s3


def sevs(findings):
    return {f["severity"] for f in findings}


class PrincipalTests(unittest.TestCase):
    def test_public(self):
        self.assertTrue(s3.is_public_principal("*"))
        self.assertTrue(s3.is_public_principal({"AWS": "*"}))
        self.assertTrue(s3.is_public_principal({"AWS": ["*", "arn:x"]}))

    def test_not_public(self):
        self.assertFalse(s3.is_public_principal({"AWS": "arn:aws:iam::1:role/x"}))


class PolicyTests(unittest.TestCase):
    def test_public_read_is_high(self):
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*",
                                 "Action": ["s3:GetObject"], "Resource": "*"}]}
        self.assertIn("high", sevs(s3.analyze_policy(policy)))

    def test_public_write_is_critical(self):
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*",
                                 "Action": ["s3:PutObject"], "Resource": "*"}]}
        self.assertIn("critical", sevs(s3.analyze_policy(policy)))

    def test_condition_downgrades(self):
        policy = {"Statement": [{"Effect": "Allow", "Principal": "*",
                                 "Action": ["s3:GetObject"], "Resource": "*",
                                 "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}
        findings = s3.analyze_policy(policy)
        self.assertNotIn("high", sevs(findings))
        self.assertIn("medium", sevs(findings))

    def test_missing_tls_deny_flagged(self):
        policy = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:x"},
                                 "Action": ["s3:GetObject"], "Resource": "*"}]}
        self.assertTrue(any("TLS-only" in f["message"] for f in s3.analyze_policy(policy)))


class AclTests(unittest.TestCase):
    def test_allusers_high(self):
        acl = {"grants": [{"grantee": {"uri": s3.ALLUSERS}, "permission": "READ"}]}
        self.assertIn("high", sevs(s3.analyze_acl(acl)))


class PabTests(unittest.TestCase):
    def test_pab_off_flagged(self):
        self.assertIn("medium", sevs(s3.analyze_pab({"BlockPublicAcls": False})))

    def test_pab_on_clean(self):
        pab = {k: True for k in s3.PAB_SETTINGS}
        self.assertEqual(s3.analyze_pab(pab), [])


if __name__ == "__main__":
    unittest.main()
