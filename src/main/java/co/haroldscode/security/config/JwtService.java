package co.haroldscode.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

	private static final String SECRET_KEY = "00b28427f2065c7471a3e03ee16ecbc0632b27c4d17708c803f8087a588e3aae";

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	/**
	 * Easier way to extract al claims using .apply from generic function
	 */
	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extraAllClaims(token);
		return claimsResolver.apply(claims);
	}

	/**
	 * "new HashMap<>()" generate a empty Map
	 */
	public String generateToken(
			UserDetails userDetails
	) {
		return generateToken(new HashMap<>(), userDetails);
	}

	public String generateToken(
			Map<String, Object> extraClaims,
			UserDetails userDetails
	) {
		return Jwts
			.builder()
				.setClaims(extraClaims)
				.setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
				.signWith(getSignInKey(), SignatureAlgorithm.HS256)
				.compact();
	}

	/**
	 * In this case we use String because the subject is
	 * a String and not an Object.
	 */
	public boolean isTokenValid(String token, UserDetails userDetails){
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration)
;	}

	private Claims extraAllClaims(String token) {
		return Jwts
				.parserBuilder()
				.setSigningKey(getSignInKey())
				.build()
				.parseClaimsJws(token)
				.getBody();
	}

	private Key getSignInKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
