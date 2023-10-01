main:
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -F
	sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
	mkdir -p ssl_log
	cp mitm.py mitm_attack && cp pharm.py pharm_attack
	chmod +x mitm_attack pharm_attack
	openssl genrsa -out ca.key 4096
	openssl req -new -x509 -days 1096 -key ca.key -out ca.crt -subj '/C=TW/L=Taipei/O=NYCU/OU=HSINCHU'

clean:
	rm -rf ssl_log
	rm -f ca.key ca.crt
	rm -f mitm_attack pharm_attack
