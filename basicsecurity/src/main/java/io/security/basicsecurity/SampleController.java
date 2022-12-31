package io.security.basicsecurity;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
public class SampleController {

    @PostMapping("/sample")
    public Student sample(@Valid @RequestBody Student student){
        System.out.println("student = " + student);
        return student;
    }

    @PostMapping("/sample/v2")
    public StudentV2 sample(@Valid @RequestBody StudentV2 student){
        System.out.println("student = " + student);
        return student;
    }

}
