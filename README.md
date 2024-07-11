# tinap

# Idea
A Client and Server that uses OPAQUE for the key exchange so a user can authenticate securely and the server doesn't need to store the password in any form.

The Client will also enforce that the user uses a randomly generated password. This implicitly requires the user to make use of a password manager.
This combination of a randomized password and limited information on the server leads to a less risky authentication experience.

Also want to investigate APIs with password manager so there is some more convenience around storing the randomly generated password. Leading to an overall convenient and secure experience with authenticating.
