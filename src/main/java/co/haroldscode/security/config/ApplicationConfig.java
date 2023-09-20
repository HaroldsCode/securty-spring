package co.haroldscode.security.config;

import co.haroldscode.security.user.data.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

	private final UserRepository userRepository;

	@Bean
	public UserDetailsService userDetailsService() {
		return username -> userRepository.findUserByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("User not found"));
	}
}
