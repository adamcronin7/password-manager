# Introduction
I decided to start this small project to create a program that practically uses cryptography, after
researching possible projects, the idea to create a password manager interested me.

After researching other projects like this in python, I found many simple implementations, so I decided
to add extra functionality to this project by adding user authentication and an encryption method for
the stored data. Having a good theoretical knowledge of encryption already meant I came up with a concept 
for my project very quickly, but as I have never tried to implement any encryption methods into a project 
before, I had to research possible ways to do this in my chosen language, python.

# Encryption Method
This password manager uses a locally stored salt and a user input password to create an encryption 
key using the PBKDF2HMAC module in python. This key is then used to encrypt and decrypt the data 
using the fernet module. The encrypted data is also locally stored.

I chose this method as using a master password means authentication will be required each time they
try to encrypt or decrypt their data. This means that if someone were to gain access to their local 
file system there is added security as the key can not be found locally in a single file and they would 
be required to know the user's master password.

# User Functions
### Functions included
I decided to add a fair bit of functionality to improve usability. There is a central menu that the
program will always return to after each action is completed. There are a total of 6 actions a user 
can perform (not including quit):

1. Add a password
2. Retrieve all passwords
3. Retrieve a specific password
4. Remove all passwords
5. Remove a specific password
6. Change master password

The user needs to authenticate whenever performing an action.

### Implementing these functions
After creating the menu and cryptography functionality I started by implementing the more simple user 
functions such as adding a password and retrieving all passwords. The add password function required me 
to take user input and encrypt it, then write it to the csv file, to retrieve these passwords, the
data needed to be read and each row needed to be decrypted and printed to the user.

Creating the ability to retrieve a specific password meant for each line, the decrypted service was
checked to see if it matched the user input. If it did, that row was decrypted and printed to the user.

Removing all passwords was very simple to implement, I did this by clearing the file using the truncate 
function in python.

Initially I thought removing specific passwords would be done as simply as the retrieve functions. 
However upon implementing them, I found there was no built in function to remove a line from a csv file. 
Upon researching I found one of the best ways to do this was to create a list in python and adding rows
that do not have the specified service that the user chose to remove. This meant that at the end I could
clear the entire file and re write the information using the rows input into the list.

Adding the ability to change a master password became more complicated with the inclusion of my encryption
method. Instead of simply changing the user's password hash stored locally, the encryption method I chose 
meant that all data was encrypted with a key created the master password. If the password was to be changed
then the data already stored would be unable to be decrypted with the new master password. My solution to 
this was to decrypt all data using the old key and re encrypt it using the new key. With the new encrypted 
data I stored each row in a list using a similar method to the function that removes a specific row. I did 
this as after each row had been re encrypted and sorted in the list, the file was cleared so it could be re
written.

# Improvements
After reviewing this project these are some initial improvements I may implement in the future or would 
have implemented if this was a larger project.

### Added Security
One way I could improve the security is by adding another layer of encryption for all sensitive input
that the user enters. This way any information such as passwords would never be handled in plain text
by the program stopping them from being temporarily stored by the local memory in plain text.

### GUI
Adding a graphical user interface would add to the user experience by creating a more user friendly
environment.

# Conclusion
Overall I am happy with this program as it contains a lot of user functionality and a strong base
level of security used to store sensitive information. Developing this has allowed me to improve my knowledge 
of python as well as explore different encryption methods and I have learnt a lot about practically implementing 
cryptography inside python.

 