package shiro;


import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Assert;
import org.junit.Test;

public class LoginLogoutTest{

	@Test
	public void testHelloworld() {
		//获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
		Factory<org.apache.shiro.mgt.SecurityManager> factory =new IniSecurityManagerFactory("classpath:shiro.ini");
		//得到SecurityManager实例 并绑定给SecurityUtils   
		SecurityManager securityManager = factory.getInstance();
		SecurityUtils.setSecurityManager(securityManager);
		//得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
		try {
			//登录，即身份验证
		    subject.login(token);
		    System.out.println("登录成功");
//	        //判断拥有角色
//	        boolean[] result = SecurityUtils.getSubject().hasRoles(Arrays.asList("role1", "role2", "role3"));
//	        System.out.println(result[0]);
//	        System.out.println(result[1]);
//	        System.out.println(result[2]);
//	        Assert.assertEquals(true, result[0]);
//	        Assert.assertEquals(true, result[1]);
//	        Assert.assertEquals(false, result[2]);
		  //断言拥有权限：user:create
		    System.out.println(SecurityUtils.getSubject().isPermitted("user:create"));
	        //断言拥有权限：user:delete and user:update
		    System.out.println(SecurityUtils.getSubject().isPermitted("user:update","user:delete")[0]);
		    String str = "hello";
		    String base64Encoded = Base64.encodeToString(str.getBytes());
		    System.out.println(str+"64编码："+base64Encoded);
		    String str2 = Base64.decodeToString(base64Encoded);
		    System.out.println(str+"64解码："+str2);
		} catch (AuthenticationException e) {
			//5、身份验证失败
			System.out.println("登录失败");
		}
		Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录
		//6、退出
		subject.logout();
	}
	@Test
	public void testCustomRealm() {
		//1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
		Factory<org.apache.shiro.mgt.SecurityManager> factory =new IniSecurityManagerFactory("classpath:shiro-realm.ini");
		//2、得到SecurityManager实例 并绑定给SecurityUtils   
		SecurityManager securityManager = factory.getInstance();
		SecurityUtils.setSecurityManager(securityManager);
		//3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken("wang", "123");
		try {
			//4、登录，即身份验证
		    subject.login(token);
		    System.out.println("登录成功");
		} catch (AuthenticationException e) {
			//5、身份验证失败
			System.out.println("登录失败");
		}
		Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录
		//6、退出
		subject.logout();
	}
	@Test
    public void testJDBCRealm() {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory("classpath:shiro-jdbc-realm.ini");
        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
      //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "1234");

        try {
            //4、登录，即身份验证
            subject.login(token);
            System.out.println("验证通过");
        } catch (AuthenticationException e) {
        	 System.out.println("验证失败");
        }

        Assert.assertEquals(true, subject.isAuthenticated()); 
        //6、退出
        subject.logout();
    }

}
