# pcap-sniffer

개발환경 
ubuntu 
언어 C

wireshark 설치 명령어 
sudo apt update 
sudo apt install -y gcc libpcap-dev net-tools wireshark

컴파일 명령어 
gcc main.c -o sniffer -lpcap
sudo ./sniffer


2025-04-04 화이트 햇 스쿨 네트워크보안 Pcap api 활용해 packet의 정보를 출력하는 프로그램 작성하기
