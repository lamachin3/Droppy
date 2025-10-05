import requests


def fetch_exegol_executables():
    ressources_list = []
    response = requests.get("https://api.github.com/repos/ThePorgs/Exegol-resources/git/trees/main?recursive=1")
    exegol_ressources = response.json()

    for ressource in exegol_ressources.get("tree", []):
        if ressource.get("path", "").endswith(".exe"):
            ressources_list.append({
                "filename": ressource["path"].split("/")[-1],
                "url": f"https://raw.githubusercontent.com/ThePorgs/Exegol-resources/refs/heads/main/{ressource['path']}",
            })
            
    return ressources_list
