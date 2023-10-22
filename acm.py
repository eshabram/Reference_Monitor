import pdb

# define my global dictonaries
file_list = {}
users = {}

###################################### File Class ###########################################

class Files:
    """
    This object represents a file from the perspective of permissions.
    It contains a simple binary string representing it's permissions scheme
    and a name.
    """
    def __init__(self, name='', priv=0b000, owner='', point=None):
        self.priv = priv
        self.name = name
        self.owner = owner
        self.point = point # allows for linking
        self.length = 1 # tracks linked list length, including self

    def grant_privilege(self, priv):
        """ Grant a privalege using a binary OR. """
        self.priv = self.priv | priv
    
    def revoke_privilege(self, priv):
        """ AND the negation of a privilege to revoke it. """
        self.priv = self.priv & ~priv 
    
    def add_link(self, file):
        """
        This add link method leverages the "point" attribute to add links to 
        the chain. It first checks whether the two files are the same, and then
        it checks whether the file is pointing to another file. If it is, we 
        move to the next file and do the check again. This will keep entries 
        unique, and allways add the entries to the end of the chain.
        """
        global file_list
        current = self
        success = False
        first = True

        while True:
            if current != file:
                first = False
                # None means that there are no permissions for this file
                if current.point is not None:
                    current = current.point
                else:
                    current.point = file
                    # add the file to the master list and increment it's tracker
                    if file.name in file_list:
                        file_list[file.name] += 1
                    else:
                        file_list[file.name] = 1
                    success = True
                    break
            else:
                current.grant_privilege(convert_orw(str(file)))
                break
        return success

    def remove_link(self, file):
        global file_list
        current = self
        prev = None

        while current is not None:
            if current == file:
                if prev is not None:
                    prev.point = current.point
                else:
                    # This is the first link in the chain
                    if current.point is not None:
                        # Move to the next link
                        current.copy_file(current.point)
                    else:
                        # This is the only link in the chain, so we delete user
                        del users[current.owner]
                self.length -= 1

                # decrement or delete from the master list
                if file_list[file.name] > 1:
                   file_list[file.name] -= 1
                else:
                    del file_list[file.name] 
                return True
            prev = current
            current = current.point
        return False
    
    def remove_privilege(self, file):
        current = self
        success = True

        while True:
            if current != file:
                # None means that there are no permissions for this file
                if current.point is not None:
                    current = current.point
                else:
                    # current.point = file
                    # this means that we didn't find the file.
                    success = False
                    break
            else:
                current.revoke_privilege(convert_orw(str(file)))
                break
        if success:
            if current.priv == 0:
                self.remove_link(file)
        return success

    def eval(self, file):
        """
        Simple method to evaluate whether a user has file permissions for a given 
        file. 
        """
        current = self
        success = False

        while True:
            if current != file:
                if current.point is not None:
                    current = current.point
                else:
                    break
            else:
                if file.get_str() in current.get_str():
                    success = True
                break
        return success

    def copy_file(self, file):
        """ This is a copy method for files. It makes things a little cleaner. """
        self.name = file.name
        self.priv = file.priv
        self.point = file.point
        self.length = file.length

    def print_links(self):
        """
        This method leverages the "point" attribute to scan through the files
        in the same manner that the add_link() method does. It will print a 
        representation of the list with file names and the associated permissions
        """
        current = self
        while True:
            if current.point is not None:
                print(f'{current.name}:{current} -> ', end='')
                current = current.point
            else:
                print(f'{current.name}:{current} -> |/|')
                break

    def get_length(self):
        
        return self.length

    def get_str(self):
        """ My str method returns the permissions in ASCII. """
        orw = ''
        if 0b100 & self.priv != 0:
            orw += 'o'
        if 0b010 & self.priv != 0:
            orw += 'r'
        if 0b001 & self.priv != 0:
            orw += 'w'
        return orw

    def __str__(self):
        """ My str method prints the permissions in ASCII. """
        orw = ''
        if 0b100 & self.priv != 0:
            orw += 'o'
        if 0b010 & self.priv != 0:
            orw += 'r'
        if 0b001 & self.priv != 0:
            orw += 'w'
        return orw
    
    def __eq__(self, other): 
        """ My eq method only needs to check that the names are the same. """
        if isinstance(other, Files):
            return self.name == other.name
        return False         
    
#############################################################################################

def load_acm(filepath):    
    global users
    tuples = []
    try:
        # read in and store the files as tuples
        with open(filepath, 'r') as file:
            tuples = [tuple(line.strip().split(',')) for line in file.readlines()]
    except Exception as e:
        print(f'Error: {e}') 
    
    for entry in tuples:
        priv = convert_orw(entry[2])
        file = Files(entry[1], priv, entry[0])

        # if user exists, add the link. Otherwise, add the user with the file
        if entry[0] in users:
            users[entry[0]].add_link(file)
        else:
            users[entry[0]] = file
            # add the file to the master list and increment it's tracker
            if file.name in file_list:
                file_list[file.name] += 1
            else:
                file_list[file.name] = 1
    return users

def convert_orw(orw):
    """ Convert privilege to binary. """
    priv = 0b000
    for c in orw:
        if c == 'o':
            priv = priv | 0b100
        if c == 'r':
            priv = priv | 0b010
        if c == 'w':
            priv = priv | 0b001
    return priv

def print_acl():
    global users
    # sort the dictionary for convenience
    users = dict(sorted(users.items()))

    print('ACL:')
    for user, file in users.items():
        print(f'User= {user} : ', end='')
        file.print_links()

def print_acm():
    global file_list
    global users
    # sort the dictionary for convenience
    users = dict(sorted(users.items()))
    file_list = dict(sorted(file_list.items()))

    # print(file_list)
    # Print columns
    print("\t" + "\t".join(file_list))

    # Iterate through users adding file permissions to a list in an organized
    # fashion, and then printing the list as a row in the matrix.
    for user, files_object in users.items():
        row = [user]
        for file in file_list:
            current = files_object
            # iterate through the Files object 
            while current is not None:
                if current.name == file:
                    # add the permissions for the user/file
                    row.append(str(current)) 
                    break
                # next file
                current = current.point 
            else:
                # empty cell
                row.append('')
        
        # Print the row for the current user
        print("\t".join(row))
    print()

def update_acm(filepath):
    global users
    tuples = []

    try:
        with open(filepath, 'r') as file:
            tuples = [tuple(line.strip().split(',')) for line in file.readlines()]
    except Exception as e:
        print(f'Error: {e}')     
        
    for entry in tuples:    
        # add the privilege
        if entry[0] == 'add':
            priv = convert_orw(entry[3])
            file = Files(entry[2], priv, entry[1])
            if entry[1] in users:
                users[entry[1]].add_link(file)
            else:
                users[entry[1]] = file
        # remove the privilege
        else:
            priv = convert_orw(entry[3])
            file = Files(entry[2], priv, entry[1])
            users[entry[1]].remove_privilege(file)
        
def eval_acm(filepath):
    global users
    tuples = []

    try:
        with open(filepath, 'r') as file:
            tuples = [tuple(line.strip().split(',')) for line in file.readlines()]
    except Exception as e:
        print(f'Error: {e}')  
    
    for entry in tuples:
        user = entry[0]
        filename = entry[1]
        priv = convert_orw(entry[2])
        if user in users:
            if filename in file_list:
                file = Files(filename, priv, user)
                permit = users[user].eval(file)
                if permit:
                    print(f'{user},{filename},{file}: \033[32mPERMIT\033[0m')
                else:
                    print(f'{user},{filename},{file}: \033[31mDENY\033[0m')

            else:
                print('File does not exist.')   
        else:
            print('User does not exist.')    

def run_acm():
    first = True
    global users
    options = ['1 - Load Entries', '2 - Print ACM', '3 - Update ACM', '4 - Evaluate requests', '5 - Exit']

    while True:
        if first:
            option = '1'
            filepath = 'input-acm-entries.txt'
            first = False
        else:
            print('\nOptions:')
            for opt in options:
                print(opt)
            option = input('Choose option (1-5): ')
            if option != '2' and option < '5':
                filepath = input('Enter the filepath: ')
            print()

        # swtich statment for the options
        if option == '1':
            users = load_acm(filepath)
        if option == '2':
            print_acm()
        if option == '3':
            filepath = 'sample-update-acm-entries.txt'
            update_acm(filepath)
        if option == '4':
            filepath = 'sample-requests.txt'
            eval_acm(filepath)
        if option == '5':
            break
        if option == '6':
            print_acl()

if __name__ == "__main__":
    run_acm()
