#Snort(suricata) rule 파일을 제작해 특정 사이트 트래픽 탐지

- test.rules 파일에 20개의 사이트를 탐지하는 룰 제작
- fast.log를 확인하면서 20개의 사이트가 제대로 탐지되는지 확인(rules 파일내의 모든 sid가 fast.log파일에 대한 모든 사이트의 로그 존재)
- 평문 통신(HTTP)이 이루어 지는 사이트 뿐만 아니라 TLS 통신(HTTPS)을 하는 사이트에 대한 탐지 구현

  (+) http : alert tcp any any -> any 80 (msg:"80 naver.com access"; content:"GET /"; content:"Host: "; content:"naver.com"; sid:10004; rev:1;)
      https : alert tcp any any -> any 443 (msg:"443 naver.com Access"; flow:to_server,established; tls_sni; content:"naver.com"; sid:10005; rev:1;)
