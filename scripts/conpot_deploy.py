import os
import subprocess

def deploy_conpot():
    dir_path = os.getcwd()
    profiles_dir = os.path.join(dir_path, "conpot_profiles/Deploy_profiles")
    folder_names = [name for name in os.listdir(profiles_dir)
                    if os.path.isdir(os.path.join(profiles_dir, name))]
    for folder in folder_names:
        template = dir_path + "/conpot_profiles/Base_profiles/" + folder
        subprocess.Popen(["conpot", "-f", "--template", template], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if __name__ == '__main__':
    deploy_conpot()