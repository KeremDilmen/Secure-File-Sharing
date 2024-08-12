# Secure File Storage and Sharing System

This project implements a secure file storage and sharing system that allows users to store, share, and manage files securely in the presence of adversaries. The system ensures confidentiality, integrity, and controlled access to files using a combination of cryptographic techniques.

## Functionality Overview

- **InitUser**: Create a new user with a username and password.
- **GetUser**: Log in an existing user using a username and password.
- **StoreFile**: Store or overwrite a file for a logged-in user.
- **LoadFile**: Retrieve file contents for a logged-in user.
- **AppendToFile**: Append data to an existing file efficiently.
- **CreateInvitation**: Generate an invitation to share a file with another user.
- **AcceptInvitation**: Accept an invitation to access a shared file.
- **RevokeAccess**: Revoke another user's access to a shared file.

## Project Structure

- **client**: Contains the main implementation of the system.
  - **`client.go`**: Core functionality for user and file operations.
  - **`client_unittest.go`**: Basic unit tests.
- **client_test**: Comprehensive tests for the system.
  - **`client_test.go`**: End-to-end testing of all functionalities.

## Design and Security

The system uses a stateless design, ensuring that all user data and file contents are securely stored in remote databases (Keystore and Datastore). The design focuses on protecting data from adversaries who may have read and write access to the Datastore. Key security mechanisms include:

- **User Authentication**: Secure user creation and login using cryptographic keys.
- **File Storage and Retrieval**: Encrypting file contents and metadata to ensure confidentiality and integrity.
- **File Sharing and Revocation**: Controlled access to files, with secure invitation and revocation mechanisms.

## Documentation

For a detailed design overview and security considerations, please refer to the [Design Document](https://drive.google.com/file/d/1_6eLeBHi03O0euRlxvWyOQeLn4zKPoiO/view?usp=sharing).
