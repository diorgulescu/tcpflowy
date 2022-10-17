import subprocess


tcp_flows = {}

output = subprocess.run(['tshark -r /mnt/c/Users/drio/work/qa/ixe-68201/pcaps/NOTQLEAN_20220916_vimeo__chrome__wf02__login_upload_video_and_logout.pcapng -nn -e tcp.stream -e ip.src -e ip.dst -Tfields -E separator=\=\- -R ip -2'], capture_output=True, text=True)

for line in output:
    flow_data = line.split('=')
    # Here, if the flow is already present in the main tcp_flows dictionary,
    # we just append the details of the current packet to the flow it belongs to.

