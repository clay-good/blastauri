import yaml

def helper(data):
    # This calls the vulnerable function
    return yaml.load(data)
