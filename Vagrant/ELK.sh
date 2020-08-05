#!/bin/bash
# cat >/etc/netplan/50-cloud-init.yaml <<EOL
# network:
#     ethernets:
#         ens33:
#             dhcp4: no
#             addresses: [192.168.38.105/24]
#             gateway4: 172.16.16.2
#             nameservers:
#                 addresses: [8.8.8.8, 8.8.4.4]
#     version: 2
#     renderer: networkd
# EOL
# sudo netplan apply

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
echo "deb [arch=amd64] https://packages.elastic.co/curator/5/debian stable main" | sudo tee -a /etc/apt/sources.list.d/curator-5.list
apt-get -qq update
apt-get -qq install elasticsearch -y # 1st install elasticseatch to get JDK
export JAVA_HOME=/usr/share/elasticsearch/jdk && echo export JAVA_HOME=/usr/share/elasticsearch/jdk >>/etc/bash.bashrc
apt-get -qq install kibana filebeat elasticsearch-curator -y

(
  crontab -l 2>/dev/null
  echo 0 0 \* \* \* curator_cli --host 192.168.38.105 delete_indices --filter_list \'{\"filtertype\": \"age\", \"source\": \"name\", \"timestring\": \"\\%Y.\\%m.\\%d\", \"unit\": \"days\", \"unit_count\": 2, \"direction\": \"older\"}\' \> /tmp/cron.log 2\>\&1
) | crontab -

cat >/etc/elasticsearch/elasticsearch.yml <<EOF
network.host: _eth1:ipv4_
discovery.type: single-node
cluster.name: cydef-es-cluster
node.name: \${HOSTNAME}
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
xpack.security.enabled: true
xpack.security.authc.api_key.enabled: true
EOF

cat >/etc/default/elasticsearch <<EOF
ES_PATH_CONF=/etc/elasticsearch
ES_STARTUP_SLEEP_TIME=5
MAX_OPEN_FILES=65536
MAX_LOCKED_MEMORY=unlimited
EOF

mkdir /etc/systemd/system/elasticsearch.service.d/
cat >/etc/systemd/system/elasticsearch.service.d/override.conf <<EOF
[Service]
LimitMEMLOCK=infinity
EOF

cat >/etc/security/limits.conf <<EOF
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
EOF

/bin/systemctl daemon-reload
/bin/systemctl enable elasticsearch.service
/bin/systemctl start elasticsearch.service

# ES has to be running before this can be ran. 
mkdir /opt/kibana/
yes | /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto >> /opt/kibana/kibana_passwords.txt
mkdir /vagrant/resources/kibana
cp /opt/kibana/kibana_passwords.txt /vagrant/resources/kibana/

KIBANA_SYS_PASS="$(grep -E "kibana_system \S .*" /opt/kibana/kibana_passwords.txt)"
ELASTIC_PASS="$(grep -E "elastic \S .*" /vagrant/resources/kibana/kibana_passwords.txt)"
KIBANA_UUID=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

#kibana
touch /var/log/kibana.log
chown kibana:kibana /var/log/kibana.log
echo server.host: \"192.168.38.105\" >>/etc/kibana/kibana.yml
echo elasticsearch.hosts: \[\"http://192.168.38.105:9200\"\] >>/etc/kibana/kibana.yml
echo logging.dest: \"/var/log/kibana.log\" >>/etc/kibana/kibana.yml

# Add Kibana security requirements
echo xpack.security.enabled: true >>/etc/kibana/kibana.yml
echo elasticsearch.username: \"kibana_system\" >>/etc/kibana/kibana.yml
printf 'elasticsearch.password: \"' >>/etc/kibana/kibana.yml
printf %s  ${KIBANA_SYS_PASS##*=}\" >>/etc/kibana/kibana.yml
printf '\nxpack.encryptedSavedObjects.encryptionKey: \"' >>/etc/kibana/kibana.yml
printf %s  ${KIBANA_UUID}\" >>/etc/kibana/kibana.yml
/bin/systemctl enable kibana.service
/bin/systemctl start kibana.service

#Logstash
# echo "http.host: \"192.168.38.105\"" >>/etc/logstash/logstash.yml
# cat >/etc/logstash/conf.d/beats-input.conf <<EOF
# input {
#   beats {
#     host => "192.168.38.105"
#     port => 5044
#   }
# }
# EOF

# cat >/etc/logstash/conf.d/syslog-filter.conf <<EOF
# filter {
#   if [type] == "syslog" {
#     grok {
#       match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
#       add_field => [ "received_at", "%{@timestamp}" ]
#       add_field => [ "received_from", "%{host}" ]
#     }
#     syslog_pri { }
#     date {
#       match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
#     }
#   }
# }
# EOF

# cat >/etc/logstash/conf.d/elasticsearch-output.conf <<EOF
# output {
#   elasticsearch {
#     hosts => ["192.168.38.105:9200"]
#     sniffing => true
#     manage_template => false
#     index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
#     #document_type => "%{[@metadata][type]}"
#   }
# }
# EOF

# echo JAVA_HOME="/usr/share/elasticsearch/jdk" >>/etc/default/logstash

# /bin/systemctl enable logstash.service
# /bin/systemctl start logstash.service

cat >/etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
- type: log
  enabled: false
  paths:
    - /var/log/auth.log
    - /var/log/syslog

filebeat.config.modules:
  path: \${path.config}/modules.d/*.yml
  reload.enabled: true
  reload.period: 10s

setup.kibana:
  host: "192.168.38.105:5601"
setup.dashboards.enabled: true

# output.logstash:
#   hosts: ["192.168.38.105:5044"]

output.elasticsearch:
  hosts: ["192.168.38.105:9200"]
EOF

echo "  "username: \"elastic\" >>/etc/filebeat/filebeat.yml
printf '  password: \"' >>/etc/filebeat/filebeat.yml
printf %s  ${ELASTIC_PASS##*=}\" >>/etc/filebeat/filebeat.yml



cat >/etc/filebeat/modules.d/osquery.yml.disabled <<EOF
- module: osquery
  result:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    var.paths: ["/var/log/kolide/osquery_result"]
EOF
filebeat --path.config /etc/filebeat modules enable osquery

#sed -i 's/enabled: true/enabled: true\n    var.paths: ["\/opt\/zeek\/logs\/current\/"]/' /etc/filebeat/modules.d/zeek.yml.disabled
mkdir /var/log/bro/; ln -s /opt/zeek/logs/current/ /var/log/bro/current
filebeat --path.config /etc/filebeat modules enable zeek

# filebeat --path.config /etc/filebeat modules enable system
filebeat --path.config /etc/filebeat modules enable suricata

# make sure kibana is up and running
#while true; do
#  result=$(curl --silent 192.168.38.105:5601/api/status)
#  if echo $result | grep -q logger; then break; fi
#  sleep 1
#done
/bin/systemctl enable filebeat.service
/bin/systemctl start filebeat.service

echo "Login to Kibana via http://192.168.38.105:5601 and use the elastic password found in /opt/kibana/kibana_passwords.txt"