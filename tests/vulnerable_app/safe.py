import yaml

def parse_config_safe(config_str):
    # SAFE: Calling yaml.safe_load which is NOT in our KB
    return yaml.safe_load(config_str)

def main():
    data = "foo: bar"
    print(parse_config_safe(data))

if __name__ == "__main__":
    main()
