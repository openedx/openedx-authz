Core Roles and Permissions: Content Library
#############################################

This document outlines the built-in roles and permissions associated with the Content Library feature in the Open edX platform.

.. contents::
    :depth: 2
    :local:

Roles
-----

A **role** is a set of permissions that defines what actions a user can perform. When you **grant a role to a user**, you assign it within a specific scope, which determines where those permissions apply. Here is the list of default roles for Libraries.

- The **Library Admin** has full control over the library, including managing users, modifying content, and handling publishing workflows. They ensure content is properly maintained and accessible as needed.

- The **Library Author** is responsible for creating, editing, and publishing content within a library. They can manage tags and collections but cannot delete libraries or manage users.

- The **Library Contributor** can create and edit content within a library but cannot publish it. They support the authoring process while leaving final publishing to Authors or Admins.

- The **Library User** can view and reuse content but cannot edit or delete anything.

Permissions
-----------

The following permissions are associated with the content library roles:

Library Permissions
=======================

- **View the library** (``view_library``): Allows users to view the content library.
- **Manage library tags** (``manage_library_tags``): Allows users to manage the tags associated with library items.
- **Delete the library** (``delete_library``): Allows users to delete the entire content library.


Library Content Permissions
===============================

- **Edit library content** (``edit_library_content``): Allows users to edit existing content within the library.
- **Publish library content** (``publish_library_content``): Allows users to publish content to or from the library.
- **Reuse library content** (``reuse_library_content``): Allows users to reuse content from the library in other contexts.


Library Team Permissions
=============================

- **View the library team** (``view_library_team``): Allows users to view the list of users or roles associated with the library.
- **Manage the library team** (``manage_library_team``): Allows users to add, remove, or change the roles of users in the library team.


Library Collections Permissions
===================================

- **Create library collections** (``create_library_collection``): Allows users to create new collections within the library.
- **Edit library collections** (``edit_library_collection``): Allows users to modify existing collections within the library.
- **Delete library collections** (``delete_library_collection``): Allows users to delete collections within the library.

Permissions Inheritance
========================

* **Managing library tags** (``manage_library_tags``) implies **editing library content** (``edit_library_content``).
* **Deleting the library** (``delete_library``) implies **editing library content** (``edit_library_content``).
* **Publishing library content** (``publish_library_content``) implies **editing library content** (``edit_library_content``).
* **Editing library content** (``edit_library_content``) implies **viewing the library** (``view_library``).
* **Reusing library content** (``reuse_library_content``) implies **viewing the library** (``view_library``).
* **Publishing library content** (``publish_library_content``) implies **viewing the library** (``view_library``).
* **Managing the library team** (``manage_library_team``) implies **viewing the library team** (``view_library_team``).
* **Deleting a library collection** (``delete_library_collection``) implies **editing a library collection** (``edit_library_collection``).
* **Creating a library collection** (``create_library_collection``) implies **editing a library collection** (``edit_library_collection``).
* **Editing a library collection** (``edit_library_collection``) implies **viewing the library** (``view_library``).


Roles and Permissions Summary Table
------------------------------------

.. table:: Matrix of Content Library Roles and Permissions
   :widths: auto

   ============================= ================= ================ ===================== ==============
   Permissions                   Library Admin     Library Author   Library Contributor   Library User
   ============================= ================= ================ ===================== ==============
   **Library**
   view_library                  ✅                 ✅                ✅                      ✅
   manage_library_tags           ✅                 ✅                ✅                      ❌
   delete_library                ✅                 ❌                ❌                      ❌
   **Content**
   edit_library_content          ✅                 ✅                ✅                      ❌
   publish_library_content       ✅                 ✅                ❌                      ❌
   reuse_library_content         ✅                 ✅                ✅                      ✅
   **Team**
   view_library_team             ✅                 ✅                ✅                      ✅
   manage_library_team           ✅                 ❌                ❌                      ❌
   **Collections**
   create_library_collection     ✅                 ✅                ✅                      ❌
   edit_library_collection       ✅                 ✅                ✅                      ❌
   delete_library_collection     ✅                 ✅                ✅                      ❌
   ============================= ================= ================ ===================== ==============


**Maintenance chart**

+--------------+-------------------------------+----------------+--------------------------------+
| Review Date  | Working Group Reviewer        | Release        | Test situation                 |
+--------------+-------------------------------+----------------+--------------------------------+
| 2025-10-13   | RBAC Project                  | Ulmo           | TO DO                          |
+--------------+-------------------------------+----------------+--------------------------------+
