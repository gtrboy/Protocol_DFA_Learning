package gtrboy.learning.learn;


import de.learnlib.drivers.api.TestDriver;
import de.learnlib.drivers.reflect.ConcreteMethodInput;
import de.learnlib.mapper.api.SULMapper;
import net.automatalib.words.Alphabet;
import net.automatalib.words.GrowingAlphabet;
import net.automatalib.words.impl.GrowingMapAlphabet;
//import net.automatalib.words.impl.SimpleAlphabet;

import java.util.List;

public class DriverSUL extends TestDriver<String, String, ConcreteMethodInput, Object>{

    // GrowingMapAlphabet: 支持添加内容的字符集，基于Map，比之前SimpleAlphabet更快，因为后者是list方式访问。
    private final GrowingAlphabet<String> alphabet = new GrowingMapAlphabet<>();

    public DriverSUL(SULMapper<String, String, ConcreteMethodInput, Object> mapper) {
        super(mapper);
    }

    public void addAlphabet(List<String> inputs){
        alphabet.addAll(inputs);
    }

    public Alphabet<String> getAlphabet(){ return this.alphabet;}

}
