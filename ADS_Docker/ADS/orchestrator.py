import docker
import time

def list_containers():
    client = docker.from_env()
    containers = client.containers.list()
    print("Currently running containers:")
    for container in containers:
        print(f"- {container.name}")

def main():
    print("Orchestrator started. Monitoring Docker containers...")
    while True:
        list_containers()
        time.sleep(10)  # wait 10 seconds between checks

if __name__ == "__main__":
    main()
