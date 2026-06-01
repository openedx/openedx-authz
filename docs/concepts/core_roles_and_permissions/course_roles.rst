.. _Roles Permissions Course:

Core Roles and Permissions: Course
##################################

This document outlines the built-in roles and permissions associated with the Course feature in the Open edX platform.

.. contents::
    :depth: 2
    :local:

.. _Course Roles:

Roles
-----

A **role** is a set of permissions that defines what actions a user can perform. When you **grant a role to a user**, you assign it within a specific scope, which determines where those permissions apply. Here is the list of default roles for Courses.

- The **Course Admin** has full control over the course, including managing users, modifying content, and handling publishing workflows. They ensure content is properly maintained and accessible as needed.

- The **Course Staff** is responsible for creating, editing, and publishing content within a course. They can manage tags and advanced settings but cannot delete courses or manage users.

- The **Course Editor** can create and edit content within a course but cannot publish it. They support the authoring process while leaving final publishing to Staff or Admins.

- The **Course Auditor** provides view-only access for general oversight, compliance review, and QA. This role cannot edit, delete, or modify any content in Studio.

.. note::

   Global staff and superusers are like Course Admins on all courses (they have full permissions across all courses by default).

Permissions
-----------

The following permissions are associated with the course roles:

Course Access & Content
=========================
- **View course** (``courses.view_course``): Allows users to view the course and access the course outline in read-only mode.
- **Create course** (``courses.create_course``): Allows users to create a new course in Studio.
- **Edit course content** (``courses.edit_course_content``): Allows users to edit course content, outline, units, and components.
- **Publish course content** (``courses.publish_course_content``): Allows users to publish course content.

Library Updates
========================
- **Manage library updates** (``courses.manage_library_updates``): Allows users to accept or reject library updates in Studio.

Course Updates & Handouts
===========================
- **View course updates** (``courses.view_course_updates``): Allows users to view course updates and handouts.
- **Manage course updates** (``courses.manage_course_updates``): Allows users to manage course updates and handouts, including creating, editing, and deleting.

Pages & Resources
====================
- **View pages & resources** (``courses.view_pages_and_resources``): Allows users to view pages and resources.
- **Manage pages & resources** (``courses.manage_pages_and_resources``): Allows users to edit pages and resources, including toggles and content managed from that section.

Files
=======
- **View files** (``courses.view_files``): Allows users to view the Files page.
- **Create files** (``courses.create_files``): Allows users to upload files.
- **Edit files** (``courses.edit_files``): Allows users to perform non-destructive file actions, such as lock or unlock.
- **Delete files** (``courses.delete_files``): Allows users to delete files.

Schedule & Details
===================
- **View schedule and details** (``courses.view_schedule_and_details``): Allows users to view the course schedule and details.
- **Edit schedule** (``courses.edit_schedule``): Allows users to edit the course schedule.
- **Edit course details** (``courses.edit_details``): Allows users to edit course details, including summary, pacing, and prerequisites.

Grading
=========
- **View grading settings** (``courses.view_grading_settings``): Allows users to view grading settings.
- **Edit grading settings** (``courses.edit_grading_settings``): Allows users to edit grading settings.

Course Team & Groups
====================
- **View course team** (``courses.view_course_team``): Allows users to view the course team roster.
- **Manage course team** (``courses.manage_course_team``): Allows users to edit course team membership and roles.
- **Manage group configuration** (``courses.manage_group_configurations``): Allows users to manage content groups.

Tags & Taxonomies
=================
- **Manage tags** (``courses.manage_tags``): Allows users to create, edit, and delete tags.
- **Manage taxonomies** (``courses.manage_taxonomies``): Allows users to create, edit, and delete taxonomies.

Advanced & Certificates
=======================
- **Manage advanced settings** (``courses.manage_advanced_settings``): Allows users to access and edit advanced settings.
- **Manage certificates** (``courses.manage_certificates``): Allows users to access and edit certificates.

Import / Export
================
- **Import course** (``courses.import_course``): Allows users to import course content.
- **Export course** (``courses.export_course``): Allows users to export course content.
- **Export tags** (``courses.export_tags``): Allows users to export tags.

Other
=====
- **View checklists** (``courses.view_checklists``): Allows users to view checklists.

.. _Course RP Summary Table:

Roles and Permissions Summary Table
-----------------------------------

.. START COURSE RP TABLE:

.. table:: Matrix of Course Roles and Permissions
   :widths: auto

   ============================================= ============== ============== ===================== ==============
   Permissions                                   Course Admin   Course Staff   Course Editor         Course Auditor
   ============================================= ============== ============== ===================== ==============
   **Tags & Taxonomies**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_tags                           ✅             ✅             ✅                    ❌
   courses.manage_taxonomies                     ✅             ❌             ❌                    ❌
   **Updates & Handouts**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course_updates                   ✅             ✅             ✅                    ✅
   courses.manage_course_updates                 ✅             ✅             ✅                    ❌
   **Advanced & Certificates**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_advanced_settings              ✅             ✅             ❌                    ❌
   courses.manage_certificates                   ✅             ✅             ❌                    ❌
   **Access & Content**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course                           ✅             ✅             ✅                    ✅
   courses.create_course                         ❌             ❌             ❌                    ❌
   courses.publish_course_content                ✅             ✅             ❌                    ❌
   courses.edit_course_content                   ✅             ✅             ✅                    ❌
   **Files**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_files                            ✅             ✅             ✅                    ✅
   courses.create_files                          ✅             ✅             ✅                    ❌
   courses.edit_files                            ✅             ✅             ✅                    ❌
   courses.delete_files                          ✅             ✅             ❌                    ❌
   **Schedule & Details**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_schedule_and_details             ✅             ✅             ✅                    ✅
   courses.edit_schedule                         ✅             ✅             ❌                    ❌
   courses.edit_details                          ✅             ✅             ✅                    ❌
   **Library Updates**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_library_updates                ✅             ✅             ✅                    ❌
   **Grading**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_grading_settings                 ✅             ✅             ✅                    ✅
   courses.edit_grading_settings                 ✅             ✅             ✅                    ❌
   **Pages & Resources**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_pages_and_resources              ✅             ✅             ✅                    ✅
   courses.manage_pages_and_resources            ✅             ✅             ✅                    ❌
   **Import / Export**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.import_course                         ✅             ✅             ❌                    ❌
   courses.export_course                         ✅             ✅             ❌                    ❌
   courses.export_tags                           ✅             ✅             ❌                    ❌
   **Team & Groups**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course_team                      ✅             ✅             ✅                    ✅
   courses.manage_group_configurations           ✅             ✅             ✅                    ❌
   courses.manage_course_team                    ✅             ❌             ❌                    ❌
   **Other**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_checklists                       ✅             ✅             ✅                    ✅
   ============================================= ============== ============== ===================== ==============

.. END COURSE RP TABLE

**Maintenance chart**

+--------------+-------------------------------+----------------+--------------------------------+
| Review Date  | Working Group Reviewer        | Release        | Test situation                 |
+--------------+-------------------------------+----------------+--------------------------------+
| 2026-05-19   | RBAC Project                  | Verawood       | TO DO                          |
+--------------+-------------------------------+----------------+--------------------------------+
