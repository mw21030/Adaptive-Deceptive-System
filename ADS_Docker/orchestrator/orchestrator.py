import docker
import time

def deploy_base_conpot(ports):
    client = docker.from_env()
    client.containers.run("conpot", detach=True, ports={f"{ports[0]}/tcp": ports[0]})


def main():
    print("Orchestrator started. Monitoring Docker containers...")
    while True:
        list_containers()
        time.sleep(10)  # wait 10 seconds between checks

if __name__ == "__main__":
    main()
