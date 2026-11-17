# PostFlow – Content Management System

**PostFlow** is a web-based Content Management System (CMS) built with PHP and MySQL. It provides a platform where users can create and manage posts while administrators control content approval and user activities.

 **Live Website:** [https://postflow-project.free.nf/](https://postflow-project.free.nf/)

---

##  Project Overview

PostFlow simplifies content publishing and management through a role-based system. It supports Guest, User, and Admin roles, providing different levels of access and functionality.

| Component | Technology |
|---|---|
| Frontend | HTML5, CSS3, JavaScript, Bootstrap |
| Backend | PHP |
| Database | MySQL |
| Database Management | phpMyAdmin |
| Local Development | XAMPP |
| Hosting | InfinityFree |
| Version Control | Git & GitHub |

---

## ✨ Key Features

-  **User Authentication** – User registration, login, and logout.
-  **Role Management** – Guest, User, and Admin access levels.
-  **Post Creation** – Users can create and submit posts.
-  **Post Editing** – Manage and edit submitted content.
-  **Post Approval** – Administrators can approve submitted posts.
-  **Post Rejection** – Administrators can reject submitted posts.
-  **Post Status Tracking** – Users can check the approval status of their submissions.
-  **Admin Dashboard** – Manage posts and administrative activities.
-  **Responsive Interface** – User-friendly interface across different screen sizes.

---

## 🌐 Live Demo

<escape>🔗</escape> **[Visit PostFlow Website](https://postflow-project.free.nf/)**

| Deployment Detail | Information |
|---|---|
| Hosting Provider | InfinityFree |
| Domain | postflow-project.free.nf |
| Backend | PHP |
| Database | MySQL |
| Deployment | Online |

---

## 📂 Project Structure

```text
PostFlow/
│
├── index.php
├── login.php
├── logout.php
├── post-create.php
├── post-edit.php
├── register.php
├── settings.php
├── allposts.php
├── view-post.php
│
├── css/
├── uploads/
│
├── README.md
└── .gitignore
```
---

##  Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/htethtet42/phpProject.git
```

### 2. Set Up XAMPP

- Install [XAMPP](https://www.apachefriends.org/).
- Start Apache and MySQL.
- Move the project folder into the `htdocs` directory.

### 3. Create a MySQL Database

1. Open `http://localhost/phpmyadmin`.
2. Create a new database.
3. Import the required database structure from your own SQL backup.

### 4. Configure Database Connection

Create a `connect.php` file in the project root directory.

Configure it with your own database credentials.

```php
<?php

$host = "localhost";
$user = "root";
$password = "";
$database = "your_database_name";

$conn = mysqli_connect(
    $host,
    $user,
    $password,
    $database
);

if (!$conn) {
    die("Database connection failed.");
}
?>
```

### 5. Run the Application

Open your browser:

```text
http://localhost/PostFlow/
```

---

##  Hosting and Deployment

PostFlow is deployed using [InfinityFree](https://www.infinityfree.com/).

The deployment process includes:

1. Creating an InfinityFree hosting account.
2. Creating a MySQL database.
3. Importing the database through phpMyAdmin.
4. Uploading project files to the `htdocs` directory.
5. Configuring database credentials in `connect.php`.
6. Testing the website online.

**Live Website:** [https://postflow-project.free.nf/](https://postflow-project.free.nf/)

---

##  Important: Excluded Files

Some files are intentionally excluded from this public GitHub repository for security and privacy reasons.

| Excluded File | Reason |
|---|---|
| `connect.php` | Contains database connection credentials. |
| `create-admin.php` | Administrative account creation script. |
| `generate-password.php` | Password generation utility. |
| `basic_php_crud.sql` | Local database backup and SQL data. |

**Please Note:**

- These files are intentionally excluded using `.gitignore`.
- Their absence from this repository does not indicate an incomplete upload.
- Anyone cloning this project must create their own `connect.php` file.
- A compatible database structure must be prepared before running the application.
- Never upload actual database passwords or administrator credentials to a public repository.

---

##  Security Considerations

- Keep database credentials private.
- Use secure password hashing.
- Validate and sanitize user input.
- Protect administrator functions from unauthorized access.
- Avoid exposing database backups and setup scripts publicly.

---

##  Project Objectives

PostFlow was developed to demonstrate practical web development skills, including:

- PHP backend development.
- MySQL database integration.
- User authentication and authorization.
- Role-based access control.
- CRUD operations.
- Content moderation and management.
- Website deployment and hosting.

---

##  Author

**Project:** PostFlow – Content Management System

**Developer:** Ma Htet Nandar Aung ( with AI assistant)

---

⭐ **Thank you for visiting PostFlow!**

Feel free to explore the source code and try the live website.

🌐 [https://postflow-project.free.nf/](https://postflow-project.free.nf/)
