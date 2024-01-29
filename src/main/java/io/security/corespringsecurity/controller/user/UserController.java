package io.security.corespringsecurity.controller.user;


import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.annotation.PostConstruct;

@Controller
public class UserController {
	@Autowired
	private UserService userService;
	@Autowired
	private PasswordEncoder passwordEncoder;

	@GetMapping(value="/mypage")
	public String myPage() throws Exception {
		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto accountDto) {
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));
		userService.createUser(account);

		return "redirect:/";
	}

	@PostConstruct
	public void init() {
		Account account = new Account("user", passwordEncoder.encode("1111"), "abc@naver.com", "10", "ROLE_USER");
		Account account2 = new Account("manager", passwordEncoder.encode("1111"), "abc@naver.com", "10", "ROLE_MANAGER");
		Account account3 = new Account("admin", passwordEncoder.encode("1111"), "abc@naver.com", "10", "ROLE_ADMIN");
		userService.createUser(account);
		userService.createUser(account2);
		userService.createUser(account3);
	}
}
