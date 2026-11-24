import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.jar.JarFile;
import java.util.List;
public final class VerifyWrapperTypes {
 public static void main(String[] args) throws Exception {
  Path path=Path.of(args[0]);
  try(JarFile jar=new JarFile(path.toFile()); URLClassLoader loader=new URLClassLoader(new java.net.URL[]{path.toUri().toURL()},ClassLoader.getPlatformClassLoader())) {
   List<String> names=jar.stream().filter(e->e.getName().endsWith(".class")).map(e->e.getName().substring(0,e.getName().length()-6).replace('/','.')).sorted().toList();
   if(names.size()!=31) throw new IllegalArgumentException("Unexpected reviewed class inventory");
   int methods=0;
   for(String name:names) {
    Class<?> c=Class.forName(name,false,loader);
    methods+=c.getDeclaredMethods().length+c.getDeclaredConstructors().length;
    c.getDeclaredFields();
    System.out.println("STRUCTURALLY_VERIFIED_WITHOUT_INITIALIZATION "+name);
   }
   System.out.println("classes="+names.size()+" methods_and_constructors="+methods+" initialized=false invoked=false");
  }
 }
}
