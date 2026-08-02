import aireconforge.AIReconForge.*;
import aireconforge.AIReconForge;
import java.lang.reflect.*;

/** Pure-logic tests for the parts that don't need a live Burp/Montoya runtime. */
public class LogicTest {
    static int pass = 0, fail = 0;
    static void ok(String name, boolean cond) {
        if (cond) { pass++; System.out.println("PASS  " + name); }
        else { fail++; System.out.println("FAIL  " + name); }
    }

    public static void main(String[] args) throws Exception {
        // --- RateLimiter: 10/s means ~20 acquisitions take >= ~1s ---
        Object rl = ctor("aireconforge.AIReconForge$RateLimiter", new Class[]{double.class}, new Object[]{10.0});
        Method acquire = rl.getClass().getDeclaredMethod("acquire"); acquire.setAccessible(true);
        long t0 = System.currentTimeMillis();
        for (int i = 0; i < 21; i++) acquire.invoke(rl);   // burst 10 + 11 more @10/s ~= 1.0-1.1s
        long elapsed = System.currentTimeMillis() - t0;
        ok("RateLimiter throttles ~10/s (21 acquires took " + elapsed + "ms, >=900ms)", elapsed >= 900);

        // --- Txt.diffRatio: identical -> 0, very different -> high; volatile ignored ---
        Method diff = m("aireconforge.AIReconForge$Txt", "diffRatio", String.class, String.class);
        double same = (double) diff.invoke(null, "hello world foo bar", "hello world foo bar");
        ok("diffRatio identical == 0", same == 0.0);
        double bigger = (double) diff.invoke(null, "hello world foo bar", "completely different text here now");
        ok("diffRatio different >= 0.05 (" + bigger + ")", bigger >= 0.05);
        // volatile tokens (csrf/uuid/timestamp) should be normalized away -> ~0 diff
        String a = "csrf_token=abc123 user=alice ts=1700000000";
        String b = "csrf_token=zzz999 user=alice ts=1699999999";
        double vol = (double) diff.invoke(null, a, b);
        ok("diffRatio ignores volatile tokens (" + vol + " < 0.05)", vol < 0.05);

        // --- Finding.dedupKey: same URL+method+param+type collide; query values ignored ---
        Object f1 = newFinding("XSS", "https://x/a?id=1", "GET", "q");
        Object f2 = newFinding("XSS", "https://x/a?id=999", "get", "Q"); // diff query + case
        String k1 = (String) invoke(f1, "dedupKey");
        String k2 = (String) invoke(f2, "dedupKey");
        ok("dedupKey ignores query + is case-insensitive", k1.equals(k2));
        Object f3 = newFinding("SQLI", "https://x/a?id=1", "GET", "q");
        String k3 = (String) invoke(f3, "dedupKey");
        ok("dedupKey differs by vuln type", !k1.equals(k3));

        // --- Finding.confidenceLabel bands ---
        Object f = newFinding("XSS", "https://x/a", "GET", "q");
        setConf(f, 95); ok("label >=90 Verified", "Verified".equals(invoke(f, "confidenceLabel")));
        setConf(f, 72); ok("label 70-89 Firm", "Firm".equals(invoke(f, "confidenceLabel")));
        setConf(f, 55); ok("label 50-69 Needs Manual", ((String)invoke(f,"confidenceLabel")).contains("Manual"));
        setConf(f, 40); ok("label <50 Dropped", "Dropped".equals(invoke(f, "confidenceLabel")));

        System.out.println("\n==== " + pass + " PASS / " + fail + " FAIL ====");
        System.exit(fail == 0 ? 0 : 1);
    }

    static Object ctor(String cls, Class[] sig, Object[] args) throws Exception {
        Constructor<?> c = Class.forName(cls).getDeclaredConstructor(sig); c.setAccessible(true);
        return c.newInstance(args);
    }
    static Method m(String cls, String name, Class... sig) throws Exception {
        Method mm = Class.forName(cls).getDeclaredMethod(name, sig); mm.setAccessible(true); return mm;
    }
    static Object invoke(Object o, String name) throws Exception {
        Method mm = o.getClass().getDeclaredMethod(name); mm.setAccessible(true); return mm.invoke(o);
    }
    static Object newFinding(String type, String url, String method, String param) throws Exception {
        Class<?> vt = Class.forName("aireconforge.AIReconForge$VulnType");
        Object typeEnum = Enum.valueOf((Class<Enum>) vt.asSubclass(Enum.class), type);
        Constructor<?> c = Class.forName("aireconforge.AIReconForge$Finding")
            .getDeclaredConstructor(vt, String.class, String.class, String.class);
        c.setAccessible(true);
        return c.newInstance(typeEnum, url, method, param);
    }
    static void setConf(Object f, int v) throws Exception {
        Field fl = f.getClass().getDeclaredField("confidence"); fl.setAccessible(true); fl.setInt(f, v);
    }
}
