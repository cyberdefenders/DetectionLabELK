Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Set FW to accept 5985 from any IP..."
netsh advfirewall firewall add rule name="Port 5985" dir=in action=allow protocol=TCP localport=5985 remoteip=any