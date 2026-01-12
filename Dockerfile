# Utiliser l'image Python officielle
FROM python:3.9-slim

# Définir le dossier de travail dans le conteneur
WORKDIR /app

# Copier le contenu de l'API dans le conteneur
# Remarque : le chemin doit être relatif au contexte du build
COPY api/ .  

# Installer les dépendances
RUN pip install --no-cache-dir flask

# Exposer le port utilisé par Flask
EXPOSE 5000

# Commande pour lancer l'application
CMD ["python", "app.py"]
