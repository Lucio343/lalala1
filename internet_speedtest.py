import speedtest

def run_speed_test():
  print("Running internet speed test...")

  st = speedtest.Speedtest()

  print("Finding optimal server...")
  st.get_best_server()

  print("Testing download speed...")
  download_speed = st.download()

  print("Testing upload speed...")
  upload_speed = st.upload()

  print("Retrieving latency...")
  ping = st.results.ping

  download_mbps = download_speed / 1000000
  upload_mbps = upload_speed / 1000000

  print("Here are the results of your internet speed test:")
  print("\n")
  print(f"Download speed: {download_mbps:.2f} Mbps")
  print(f"Upload speed: {upload_mbps:.2f} Mbps")
  print(f"Latency (or Ping): {ping:.2f} ms")
  print("\n")

run_speed_test()