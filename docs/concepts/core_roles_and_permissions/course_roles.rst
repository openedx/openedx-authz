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

Course access & content
=======================

Permissions for accessing the course, viewing course and learner information, and managing course content.

- **View course** (``courses.view_course``): Find the course on the Studio home page and open its outline in read-only mode. Use “View Live” to preview the course as a learner in the LMS.
- **Edit course content** (``courses.edit_course_content``): Edit the course outline, units, and components.
- **Publish course content** (``courses.publish_course_content``): Make course content visible to learners.
- **View course info** (``courses.view_course_info``): View general course information, enrollment counts, and the status of background tasks in the Instructor Dashboard.
- **View checklists** (``courses.view_checklists``): See the course launch checklist in Studio.
- **View learner course status** (``courses.view_learner_course_status``): Access learner profile information, enrollment status, and course progress.

Course team
===========

Permissions for viewing course team members and managing course role assignments.

- **View course team** (``courses.view_course_team``): View course team members and their assigned roles in the Roles and Permissions console or on the Course Team tab in the Instructor Dashboard.
- **Manage course team** (``courses.manage_course_team``): Add, change, or remove role assignments for this course from the Roles and Permissions console or the Instructor Dashboard.

Schedule & details
==================

Permissions for viewing and editing the course schedule and details in Studio.

- **View schedule & details** (``courses.view_schedule_and_details``): View course start and end dates, enrollment dates, pacing, the course summary, and prerequisites.
- **Edit schedule** (``courses.edit_schedule``): Update course start and end dates, enrollment dates, and pacing settings.
- **Edit course details** (``courses.edit_details``): Update course information including the course summary, pacing, and prerequisites.

Advanced settings & certificates
================================

Permissions for viewing and managing advanced course settings and course certificates in Studio.

- **View advanced settings** (``courses.view_advanced_settings``): View advanced settings in Studio, including proctoring, timed exams, LTI tools, enrollment limits, and custom display options.
- **Manage advanced settings** (``courses.manage_advanced_settings``): Edit technical course configurations in the Advanced Settings page in Studio.
- **View certificates** (``courses.view_certificates``): See the course certificate settings.
- **Manage certificates** (``courses.manage_certificates``): Create and edit course certificates, including certificate design and eligibility settings.

Pages & resources
=================

Permissions for viewing and managing course pages and additional learning resources.

- **View pages & resources** (``courses.view_pages_and_resources``): View course pages, learning resources, and feature settings in Studio.
- **Manage pages & resources** (``courses.manage_pages_and_resources``): Turn course features such as Discussions, Wiki, Notes, Calculator, and Live on or off. Create, edit, and configure textbooks and custom pages.

Course updates & handouts
=========================

Permissions for viewing and managing course announcements and handouts.

- **View course updates** (``courses.view_course_updates``): See course announcements and handouts visible to learners.
- **Manage course updates** (``courses.manage_course_updates``): Create, edit, and delete course announcements and handouts.

Files
=====

Permissions for viewing and managing files and assets uploaded to the course.

- **View files** (``courses.view_files``): View the list of uploaded course files and assets.
- **Create files** (``courses.create_files``): Upload new files and assets to the course.
- **Edit files** (``courses.edit_files``): Perform non-destructive actions on files, such as locking or unlocking them.
- **Delete files** (``courses.delete_files``): Permanently remove files and assets from the course.

Library updates
===============

Permissions for reviewing and applying content updates from linked libraries.

- **View library updates** (``courses.view_library_updates``): Review pending updates from linked content libraries.
- **Manage library updates** (``courses.manage_library_updates``): Accept or reject pending updates from linked content libraries.

Tags
====

Permissions for managing course tags and exporting tag data.

- **Manage tags** (``courses.manage_tags``): Create, edit, and delete tags on this course.
- **Export tags** (``courses.export_tags``): Download the tag data associated with this course.

Course import & export
======================

Permissions for importing and exporting course content.

- **Import course** (``courses.import_course``): Import course content from a file. This is a high-privilege action that can overwrite most course content and settings.
- **Export course** (``courses.export_course``): Download course content as a file for backup or reuse on another platform.

Enrollments
===========

Permissions for viewing and managing learner enrollments in the Instructor Dashboard.

- **View enrollments** (``courses.view_enrollments``): View and search course enrollments and check a learner's enrollment status.
- **Enroll learners** (``courses.enroll_learners``): Enroll learners in the course, individually or in bulk.
- **Unenroll learners** (``courses.unenroll_learners``): Unenroll learners from the course.

Cohorts & content groups
========================

Permissions for organizing learners into cohorts in the Instructor Dashboard and configuring content groups in Studio.

- **View cohorts** (``courses.view_cohorts``): View course cohorts, their configuration, and their members.
- **Manage cohorts** (``courses.manage_cohorts``): Enable cohorts, create and configure them, and assign or move learners between cohorts manually or by uploading a CSV file.
- **View group configurations** (``courses.view_group_configurations``): View the course’s content groups and their settings in Studio.
- **Manage group configurations** (``courses.manage_group_configurations``): Create and configure content groups in Studio to make course content available to specific learners.

Grading settings
================

Permissions for viewing and editing course grading settings.

- **View grading settings** (``courses.view_grading_settings``): View the course's grading configuration, including assignment types and the grading scale, in Studio or from the Instructor Dashboard.
- **Edit grading settings** (``courses.edit_grading_settings``): Update the grading configuration for the course, including assignment types and grading scale.

Learner grading
===============

Permissions for viewing learner grades and using grading tools in the Instructor Dashboard.

- **View gradebook** (``courses.view_gradebook``): View grades for learners enrolled in the course.
- **Manage learner grading** (``courses.manage_learner_grading``): Use grading tools for individual learners. Reset attempts, rescore submissions, override scores, and clear saved problem state.
- **Manage bulk learner grading** (``courses.manage_bulk_learner_grading``): Use grading tools for all learners in the course. Reset attempts, rescore submissions, and clear saved problem state in bulk.

Learner extensions
==================

Permissions for viewing and managing individual learner extensions in the Instructor Dashboard.

- **View learner extensions** (``courses.view_learner_extensions``): Find granted extensions and see the updated due dates.
- **Manage learner extensions** (``courses.manage_learner_extensions``): Grant or change extensions for individual learners, or restore the original course due dates.

.. _Course RP Summary Table:

Roles and Permissions Summary Table
-----------------------------------

.. START COURSE RP TABLE:

.. table:: Matrix of Course Roles and Permissions
   :widths: auto

   ============================================= ============== ============== ===================== ==============
   Permissions                                   Course Admin   Course Staff   Course Editor         Course Auditor
   ============================================= ============== ============== ===================== ==============
   **Course access & content**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course                           ✅             ✅             ✅                    ✅
   courses.edit_course_content                   ✅             ✅             ✅                    ❌
   courses.publish_course_content                ✅             ✅             ❌                    ❌
   courses.view_course_info                      ✅             ✅             ❌                    ❌
   courses.view_checklists                       ✅             ✅             ✅                    ✅
   courses.view_learner_course_status            ✅             ✅             ❌                    ❌
   **Course team**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course_team                      ✅             ✅             ✅                    ✅
   courses.manage_course_team                    ✅             ❌             ❌                    ❌
   **Schedule & details**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_schedule_and_details             ✅             ✅             ✅                    ✅
   courses.edit_schedule                         ✅             ✅             ❌                    ❌
   courses.edit_details                          ✅             ✅             ✅                    ❌
   **Advanced settings & certificates**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_advanced_settings                ✅             ✅             ✅                    ✅
   courses.manage_advanced_settings              ✅             ✅             ❌                    ❌
   courses.view_certificates                     ✅             ✅             ✅                    ✅
   courses.manage_certificates                   ✅             ✅             ❌                    ❌
   **Pages & resources**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_pages_and_resources              ✅             ✅             ✅                    ✅
   courses.manage_pages_and_resources            ✅             ✅             ✅                    ❌
   **Course updates & handouts**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_course_updates                   ✅             ✅             ✅                    ✅
   courses.manage_course_updates                 ✅             ✅             ✅                    ❌
   **Files**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_files                            ✅             ✅             ✅                    ✅
   courses.create_files                          ✅             ✅             ✅                    ❌
   courses.edit_files                            ✅             ✅             ✅                    ❌
   courses.delete_files                          ✅             ✅             ❌                    ❌
   **Library updates**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_library_updates                  ✅             ✅             ✅                    ✅
   courses.manage_library_updates                ✅             ✅             ✅                    ❌
   **Tags**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.manage_tags                           ✅             ✅             ✅                    ❌
   courses.export_tags                           ✅             ✅             ❌                    ❌
   **Course import & export**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.import_course                         ✅             ✅             ❌                    ❌
   courses.export_course                         ✅             ✅             ❌                    ❌
   **Enrollments**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_enrollments                      ✅             ✅             ❌                    ❌
   courses.enroll_learners                       ✅             ✅             ❌                    ❌
   courses.unenroll_learners                     ✅             ✅             ❌                    ❌
   **Cohorts & content groups**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_cohorts                          ✅             ✅             ❌                    ❌
   courses.manage_cohorts                        ✅             ✅             ❌                    ❌
   courses.view_group_configurations             ✅             ✅             ✅                    ✅
   courses.manage_group_configurations           ✅             ✅             ✅                    ❌
   **Grading settings**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_grading_settings                 ✅             ✅             ✅                    ✅
   courses.edit_grading_settings                 ✅             ✅             ✅                    ❌
   **Learner grading**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_gradebook                        ✅             ✅             ❌                    ❌
   courses.manage_learner_grading                ✅             ✅             ❌                    ❌
   courses.manage_bulk_learner_grading           ✅             ❌             ❌                    ❌
   **Learner extensions**
   --------------------------------------------- -------------- -------------- --------------------- --------------
   courses.view_learner_extensions               ✅             ✅             ❌                    ❌
   courses.manage_learner_extensions             ✅             ✅             ❌                    ❌
   ============================================= ============== ============== ===================== ==============

This matrix shows which permissions each course role grants across Studio, the Instructor Dashboard, and the Roles and Permissions console. Some roles may also grant permissions managed elsewhere.

.. END COURSE RP TABLE

**Maintenance chart**

+--------------+-------------------------------+----------------+--------------------------------+
| Review Date  | Working Group Reviewer        | Release        | Test situation                 |
+--------------+-------------------------------+----------------+--------------------------------+
| 2026-05-19   | RBAC Project                  | Verawood       | TO DO                          |
+--------------+-------------------------------+----------------+--------------------------------+
