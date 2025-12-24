from .utils import helper

def app_controller():
    # Helper calls vulnerable yaml.load
    helper("foo: bar")

if __name__ == "__main__":
    app_controller()
