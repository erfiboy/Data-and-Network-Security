class Access_control:

    def __init__(self,n ,m) :

        self.n = n
        self.m = m
        self.user_list = dict()
        self.file_list = dict()
        self.table = [[-1]*m]*n

    def add_user(self, user_name) :

        index = len(self.user_list)
        self.user_list[user_name] = index

    def add_file(self, file_name) :

        index = len(self.file_list)
        self.file_list[file_name] = index

    def edit_access(self, user, file , access) :

        file_ind = self.file_list[file]
        user_ind = self.user_list[user]
        self.table[user_ind][file_ind] = access

    def get_access(self, user, file):

        file_ind = self.file_list[file]
        user_ind = self.user_list[user]

        return self.table[user_ind][file_ind]
