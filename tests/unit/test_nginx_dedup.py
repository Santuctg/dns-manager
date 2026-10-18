from app.services.nginx_dedup import remove_ssl_owned_http_blocks


def test_057_removes_only_ssl_owned_http_server_block():
    text = '''# header\nserver {\n    listen 80;\n    server_name vm226.connect3.net.bd;\n    location / {\n        proxy_pass https://192.168.255.226:443;\n    }\n}\n\nserver {\n    listen 80;\n    server_name plain.connect3.net.bd;\n    location / {\n        proxy_pass http://192.168.255.50:8080;\n    }\n}\n'''
    result = remove_ssl_owned_http_blocks(text, {"vm226.connect3.net.bd"})
    assert "server_name vm226.connect3.net.bd;" not in result
    assert "server_name plain.connect3.net.bd;" in result
    assert "proxy_pass http://192.168.255.50:8080;" in result


def test_057_dedup_is_noop_for_unknown_domain():
    text = '''# header\nserver {\n    listen 80;\n    server_name plain.connect3.net.bd;\n    location / { proxy_pass http://192.168.255.50:8080; }\n}\n'''
    assert remove_ssl_owned_http_blocks(text, {"vm226.connect3.net.bd"}) == text
