package com.densoft.springsecuritydemo.controllers;

import com.densoft.springsecuritydemo.model.Student;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
//    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')") //method level security
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
//    @PreAuthorize("hasAuthority('student:write')") //method level security
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }


    @DeleteMapping("/{studentId}")
//    @PreAuthorize("hasAuthority('student:write')") //method level security
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println(studentId);
    }

    @PutMapping("/{studentId}")
//    @PreAuthorize("hasAuthority('student:write')") //method level security
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println(String.format("%s %s", studentId, student));
    }
}
