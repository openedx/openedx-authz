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

- The **Course Contributor** can create and edit content within a course but cannot publish it. They support the authoring process while leaving final publishing to Staff or Admins.

- The **Course Auditor** can view and reuse content but cannot edit or delete anything.

.. note::

   Global staff and superusers are like Course Admins on all courses (they have full permissions across all courses by default).

Permissions
-----------

The following permissions are associated with the course roles:

Course Permissions
==================

- **View course** (``courses.view_course``): Allows users to view the course and access the course outline in read-only mode.
- **Create course** (``courses.create_course``): Allows users to create a new course in Studio.
- **Edit course content** (``courses.edit_course_content``): Allows users to edit course content, outline, units, and components.
- **Publish course content** (``courses.publish_course_content``): Allows users to publish course content.
- **Review library updates** (``courses.manage_library_updates``): Allows users to accept or reject library updates in Studio.
- **View course updates** (``courses.view_course_updates``): Allows users to view course updates and handouts.
- **Manage course updates** (``courses.manage_course_updates``): Allows users to manage course updates and handouts, including creating, editing, and deleting.
- **View pages & resources** (``courses.view_pages_and_resources``): Allows users to view pages and resources.
- **Manage pages & resources** (``courses.manage_pages_and_resources``): Allows users to edit pages and resources, including toggles and content managed from that section.
- **View files** (``courses.view_files``): Allows users to view the Files page.
- **Create files** (``courses.create_files``): Allows users to upload files.
- **Edit files** (``courses.edit_files``): Allows users to perform non-destructive file actions, such as lock or unlock.
- **Delete files** (``courses.delete_files``): Allows users to delete files.
- **View schedule** (``courses.view_schedule``): Allows users to view the course schedule.
- **Edit schedule** (``courses.edit_schedule``): Allows users to edit the course schedule.
- **View course details** (``courses.view_details``): Allows users to view course details.
- **Edit course details** (``courses.edit_details``): Allows users to edit course details, including summary, pacing, and prerequisites.
- **View grading settings** (``courses.view_grading_settings``): Allows users to view grading settings.
- **Edit grading settings** (``courses.edit_grading_settings``): Allows users to edit grading settings.
- **View course team** (``courses.view_course_team``): Allows users to view the course team roster.
- **Manage course team** (``courses.manage_course_team``): Allows users to edit course team membership and roles.
- **Manage group configuration** (``courses.manage_group_configurations``): Allows users to manage content groups.
- **Manage tags** (``courses.manage_tags``): Allows users to create, edit, and delete tags.
- **Manage taxonomies** (``courses.manage_taxonomies``): Allows users to create, edit, and delete taxonomies.
- **Manage advanced settings** (``courses.manage_advanced_settings``): Allows users to access and edit advanced settings.
- **Manage certificates** (``courses.manage_certificates``): Allows users to access and edit certificates.
- **Import course** (``courses.import_course``): Allows users to import course content.
- **Export course** (``courses.export_course``): Allows users to export course content.
- **Export tags** (``courses.export_tags``): Allows users to export tags.
- **View checklists** (``courses.view_checklists``): Allows users to view checklists.
- **View global staff & super admins** (``courses.view_global_staff_and_superadmins``): Allows course admins to view the list of global staff and super admin users.

.. _Course RP Summary Table:

Roles and Permissions Summary Table
-----------------------------------

.. START COURSE RP TABLE:

.. table:: Matrix of Course Roles and Permissions
   :widths: auto

   ============================================= ============== ============== ===================== ==============
   Permissions                                   Course Admin   Course Staff   Course Contributor    Course Auditor
   ============================================= ============== ============== ===================== ==============
   **Access & Content**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course                           ✅             ✅             ✅                    ✅
   courses.create_course                         ✅             ✅             ✅                    ❌
   courses.edit_course_content                   ✅             ✅             ✅                    ❌
   courses.publish_course_content                ✅             ✅             ❌                    ❌
   **Library Updates**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_library_updates                ✅             ✅             ❌                    ❌
   **Updates & Handouts**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course_updates                   ✅             ✅             ✅                    ✅
   courses.manage_course_updates                 ✅             ✅             ❌                    ❌
   **Pages & Resources**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_pages_and_resources              ✅             ✅             ✅                    ✅
   courses.manage_pages_and_resources            ✅             ✅             ❌                    ❌
   **Files**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_files                            ✅             ✅             ✅                    ✅
   courses.create_files                          ✅             ✅             ✅                    ❌
   courses.edit_files                            ✅             ✅             ✅                    ❌
   courses.delete_files                          ✅             ✅             ❌                    ❌
   **Schedule & Details**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_schedule                         ✅             ✅             ✅                    ✅
   courses.edit_schedule                         ✅             ✅             ❌                    ❌
   courses.view_details                          ✅             ✅             ✅                    ✅
   courses.edit_details                          ✅             ✅             ❌                    ❌
   **Grading**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_grading_settings                 ✅             ✅             ✅                    ✅
   courses.edit_grading_settings                 ✅             ✅             ❌                    ❌
   **Team & Groups**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course_team                      ✅             ✅             ✅                    ✅
   courses.manage_course_team                    ✅             ❌             ❌                    ❌
   courses.manage_group_configurations           ✅             ✅             ❌                    ❌
   **Tags & Taxonomies**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_tags                           ✅             ✅             ❌                    ❌
   courses.manage_taxonomies                     ✅             ✅             ❌                    ❌
   **Advanced & Certificates**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_advanced_settings              ✅             ✅             ❌                    ❌
   courses.manage_certificates                   ✅             ✅             ❌                    ❌
   **Import / Export**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.import_course                         ✅             ❌             ❌                    ❌
   courses.export_course                         ✅             ✅             ❌                    ❌
   courses.export_tags                           ✅             ✅             ❌                    ❌
   **Other**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_checklists                       ✅             ✅             ✅                    ✅
   courses.view_global_staff_and_superadmins     ✅             ❌             ❌                    ❌
   ============================================= ============== ============== ===================== ==============

.. END COURSE RP TABLE

**Maintenance chart**

+--------------+-------------------------------+----------------+--------------------------------+
| Review Date  | Working Group Reviewer        | Release        | Test situation                 |
+--------------+-------------------------------+----------------+--------------------------------+
| 2026-05-19   | RBAC Project                  | Verawood       | TO DO                          |
+--------------+-------------------------------+----------------+--------------------------------+
