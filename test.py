from notebook.url_analyzer import get_url_features

url = "https://example.com"

features = get_url_features(url)

for name, value in features.items():
    print(name, ":", value)