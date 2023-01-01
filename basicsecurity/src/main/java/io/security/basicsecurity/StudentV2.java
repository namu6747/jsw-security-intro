package io.security.basicsecurity;

import lombok.Builder;
import org.springframework.util.StringUtils;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

public class StudentV2 {

    @NotNull
    private Integer age;
    private String name;
    @NotBlank
    private String location;
    private Long fhd;
    private String required;

    @Builder
    public StudentV2(String name, Integer age, String location, String required, String fhd) {
        System.out.println("in builder");
        this.fhd = Long.valueOf(fhd);
        this.age = age + 1;
        this.name = name + 1;
        this.location = StringUtils.hasLength(location) ? location + "값 확인" : null;
        this.required = required + 1;
    }

    public Integer getAge() {
        return age;
    }

    public String getName() {
        return name;
    }

    public String getLocation() {
        return location;
    }

    public Long getFhd() {
        return fhd;
    }

    public String getRequired() {
        return required;
    }
}
