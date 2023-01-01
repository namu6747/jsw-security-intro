package io.security.basicsecurity;

import lombok.*;
import org.springframework.util.StringUtils;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class Student {

    @NotBlank
    private String age;
    @NotNull @Valid
    private School school;

    public static class School{
        private String name;
        @NotBlank
        private String location;
        private String required;

        public School(String name, String location, String required){
            System.out.println("in");
            this.name= StringUtils.hasLength(name) ? name : null;
            this.location= location;
        }

        public String getName() {
            return name;
        }

        public String getLocation() {
            return location;
        }

        public String getRequired() {
            return required;
        }
    }

    public String getAge() {
        return age;
    }

    public void setAge(String age) {
        this.age = age;
    }

    public School getSchool() {
        return school;
    }

    public void setSchool(School school) {
        this.school = school;
    }
}
