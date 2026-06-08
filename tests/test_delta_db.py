def test_add_domain(mock_db):
    """Verify that adding a domain persists and returns an ID."""
    domain = "example.com"
    domain_id = mock_db.add_domain(domain)
    assert domain_id > 0
    
    # Verify persistence using the correct column 'domain'
    with mock_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM domains WHERE domain = ?", (domain,))
        row = cursor.fetchone()
        assert row is not None
        assert row[0] == domain_id

def test_add_subdomain(mock_db):
    """Verify subdomain insertion works."""
    domain_id = mock_db.add_domain("example.com")
    subdomain = "dev.example.com"
    
    with mock_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO subdomains (domain_id, subdomain) VALUES (?, ?)', (domain_id, subdomain))
        
    with mock_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM subdomains WHERE subdomain = ?", (subdomain,))
        row = cursor.fetchone()
        assert row is not None