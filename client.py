
class Client():
    client_name = ""
    client_response = ""

    def __init__(self, client_name = "Yushen"):
        self.client_name = client_name

    def get_name(self):
        return self.client_name


if __name__ == '__main__':
    test_object = None
    while True:
        object_name = raw_input()
        if object_name == "":
            test_object = Client()
        else:
            test_object = Client(object_name)
        print "The client name is", test_object.get_name()

