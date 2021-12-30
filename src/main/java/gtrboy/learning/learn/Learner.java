package gtrboy.learning.learn;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.lstar.ce.ObservationTableCEXHandlers;
import de.learnlib.algorithms.lstar.closing.ClosingStrategies;
import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealy;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealy;
import de.learnlib.api.SUL;
import de.learnlib.api.oracle.EquivalenceOracle;
import de.learnlib.api.statistic.StatisticSUL;
import de.learnlib.drivers.reflect.ConcreteMethodInput;
import de.learnlib.filter.cache.sul.SULCaches;
import de.learnlib.filter.statistic.sul.ResetCounterSUL;
import de.learnlib.mapper.api.SULMapper;
import de.learnlib.oracle.equivalence.mealy.RandomWalkEQOracle;
import de.learnlib.oracle.membership.SULOracle;
import de.learnlib.util.Experiment;
import de.learnlib.util.statistics.SimpleProfiler;
import gtrboy.learning.utils.DataUtils;
import net.automatalib.visualization.Visualization;
// import sut.Driver;

import net.automatalib.automata.transducers.MealyMachine;
import net.automatalib.serialization.dot.GraphDOT;
import net.automatalib.words.Word;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

public class Learner {
    private final SULMapper<String, String, ConcreteMethodInput, Object> mapper;
    private static final String MODEL_DIR = "learnedModels/";
    private static final int SEED = 18021996;
    private final Logger LOGGER = LogManager.getLogger(LogManager.ROOT_LOGGER_NAME);

    public Learner(SULMapper<String, String, ConcreteMethodInput, Object> mapper){
        this.mapper = mapper;
    }

    //public Experiment.MealyExperiment<String, String> learn(int numSteps, String experimentName, List<String> inputAlphabet) throws IOException {
    public void learn(int numSteps, String experimentName, List<String> inputAlphabet) throws IOException {
        double resetProbability = 0.09;

        DriverSUL sul = new DriverSUL(mapper);

        // 2 clients - publisher and reader - to avoid non determinism
        // authentication
        sul.addAlphabet(inputAlphabet);

        List<Word<String>> initialSuffixes = new ArrayList<>();
        sul.getAlphabet().forEach(it -> {initialSuffixes.add(Word.fromSymbols(it));});

        StatisticSUL<String , String> statisticSul = new ResetCounterSUL<>("membership queries", sul);
        SUL<String, String> effectiveSul = statisticSul;
        effectiveSul = SULCaches.createCache(sul.getAlphabet(), effectiveSul);

        SULOracle<String, String> mqOracle = new SULOracle<>(effectiveSul);
        TTTLearnerMealy<String, String> ttt = new TTTLearnerMealy<>(sul.getAlphabet(), mqOracle, AcexAnalyzers.BINARY_SEARCH_BWD);
        ExtensibleLStarMealy<String, String> lStarMealy = new ExtensibleLStarMealy<>(sul.getAlphabet(), mqOracle, initialSuffixes, ObservationTableCEXHandlers.RIVEST_SCHAPIRE, ClosingStrategies.CLOSE_SHORTEST);

        EquivalenceOracle.MealyEquivalenceOracle<String, String> eqOracle = new RandomWalkEQOracle<>(sul, // system under learning
                resetProbability, // reset SUL w/ this probability before a step
                numSteps, // max steps (overall)
                true, // reset step count after counterexample
                new Random(SEED) // make results reproducible
        );
//        EquivalenceOracle.MealyEquivalenceOracle<String, String> eqOracle = new ExtendedEqOracle<>(driver, resetProbability, numSteps, null, null);

        Experiment.MealyExperiment<String, String> experiment = new Experiment.MealyExperiment<>(ttt, eqOracle, sul.getAlphabet());
        experiment.setProfile(true);
        experiment.setLogModels(true);

        // Start Experiment
        String dateStart = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS").format(new Date());
        long st = DataUtils.fromDateStringToLong(dateStart);
        LOGGER.info("Start Time: " + dateStart);
        try {
            experiment.run();
        } catch (Exception e){
            e.printStackTrace();
        }
        String dateEnd = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss:SSS").format(new Date());
        long et = DataUtils.fromDateStringToLong(dateEnd);
        LOGGER.info("End Time: " + dateEnd);
        float diffTime = (float) (et - st) / 1000 / 60;
        LOGGER.info("Use Time: " + diffTime + "m");

        LOGGER.info(SimpleProfiler.getResults());
        LOGGER.info(experiment.getRounds().getSummary());
        LOGGER.info(statisticSul.getStatisticalData().getSummary());


        MealyMachine<?, String, ?, String> result = experiment.getFinalHypothesis();

        // prepare model directory
        File folder = new File(MODEL_DIR);
        if (!folder.exists() && !folder.isDirectory()) {
            folder.mkdirs();
        }

        // model statistics
        LOGGER.info("States: " + result.size());
        LOGGER.info("Sigma: " + sul.getAlphabet().size());

        LOGGER.info("Model: ");
        String filepath = MODEL_DIR + experimentName + ".dot";
        LOGGER.info(filepath);
        OutputStreamWriter outputStreamWriter = new OutputStreamWriter(new FileOutputStream(filepath));
        GraphDOT.write(result, sul.getAlphabet(), outputStreamWriter); // may throw IOException!
        outputStreamWriter.flush();
        outputStreamWriter.close();
        LOGGER.info("Model written to " + filepath);
        //LearningUtil.deleteSSTandVizualize(filepath);
        //Visualization.visualize(result, sul.getAlphabet());
        //return experiment;
    }

}
