package io.security.basicsecurity;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
class BasicsecurityApplicationTests {

	@Autowired
	MockMvc mockMvc;


	@Test
	void contextLoads() {
	}

	@Test
	void mockTest()throws Exception{

		ObjectMapper om = new ObjectMapper();

		Student student = new Student();
		student.setAge("나이입니다");
		student.setSchool(new Student.School(null,null,null));



		mockMvc.perform(post("http://localhost:8080/sample")
				.content(om.writeValueAsString(student))
				.contentType(MediaType.APPLICATION_JSON)
		).andDo(print());

	}

}
