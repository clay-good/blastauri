import yaml

def parse_config(config_str):
    # UNSAFE: Calling yaml.load which is in our vulnerability KB
    return yaml.load(config_str)

def main():
    data = "foo: bar"
    print(parse_config(data))

if __name__ == "__main__":
    main()
