from pykerberize import pykerberize

def test_get_ssm_param_value( ):
    assert pykerberize._get_ssm_param_value("corp-iai-domain-name", True) == "corp.integrateai.net"

def test_get_host_principal_name( ):
    assert pykerberize._get_principal_name("host","@CORP.INTEGRATEAI.NET") is not None

def test_get_kadm_session( ):
#    assert pykerberize._get_kadm_session("admin@CORP.INTEGRATEAI.NET", "bordercollie") is not None

def test_get_principal( ):
    sess = pykerberize._get_kadm_session("admin@CORP.INTEGRATEAI.NET", "bordercollie")
    assert sess is not None

    principal = pykerberize._get_principal(sess, "host/test.corp.integrateai.net@CORP.INTEGRATEAI.NET")
    assert principal is not None

    principal = pykerberize._get_principal(sess, "madeup@CORP.INTEGRATEAI.NET")
    assert principal is None

def test_get_realm_name( ):
    assert pykerberize._get_realm_name() is not None

def test_principal_exists( ):
    sess = pykerberize._get_kadm_session("admin@CORP.INTEGRATEAI.NET", "bordercollie")
    assert sess is not None

    exists = pykerberize._principal_exists(sess, "host/test.corp.integrateai.net@CORP.INTEGRATEAI.NET")
    assert exists == True

    exists = pykerberize._principal_exists(sess, "FakeId@CORP.INTEGRATEAI.NET")
    assert exists == False

def test_create_principal( ):
    sess = pykerberize._get_kadm_session("admin@CORP.INTEGRATEAI.NET", "bordercollie")
    assert sess is not None

    created = pykerberize._create_principal(sess,"host/test.corp.integrateai.net@CORP.INTEGRATEAI.NET")
    assert created == True

def test_kadmin_ktadd( ):
    sess = pykerberize._get_kadm_session("admin@CORP.INTEGRATEAI.NET", "bordercollie")
    assert sess is not None

    kt = pykerberize._kadmin_ktadd(sess, "host/test.corp.integrateai.net@CORP.INTEGRATEAI.NET", "FILE:/root/pytest.keytab")
    assert kt 


