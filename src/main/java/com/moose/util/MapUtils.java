package com.moose.util;

import com.google.common.collect.Maps;
import org.springframework.lang.UsesJava8;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

public abstract class MapUtils {

    @UsesJava8
    public static <T, K, U> Map<K, U> transfer(Map<T, K> keyMap, Map<T, U> valueMap) {
        Assert.notNull(keyMap);
        Assert.notNull(valueMap);

        Map<K, U> result = Maps.newHashMapWithExpectedSize(keyMap.size());
        keyMap.entrySet().stream().forEach(entry -> {
            ifPresentValue(valueMap, entry.getKey(), value -> {
                result.put(entry.getValue(), value);
            });
        });
        return result;
    }

    @UsesJava8
    public static <T, K> Map<K, T> toMap(Collection<T> sourceList, Function<T, K> keyApply) {
        return toMap(sourceList, keyApply, Function.identity());
    }

    @UsesJava8
    public static <T, K, U> Map<K, U> toMap(Collection<T> sourceList, Function<T, K> keyApply, Function<T, U> valueApply) {
        Assert.notNull(sourceList);
        Assert.notNull(keyApply);
        Assert.notNull(valueApply);

        return sourceList.stream()
                .filter(ObjectUtils::isNotEmpty)
                .collect(Collectors.toMap(keyApply, valueApply));
    }

    @UsesJava8
    public static <K, V> void ifPresentValue(Map<K, V> source, K key, Consumer<V> consumer) {
        Assert.notNull(source);
        Assert.notNull(consumer);

        V value = source.get(key);
        if(value != null) {
            consumer.accept(value);
        }
    }

    @UsesJava8
    public static <K, V> void ifPresentValue(Map<K, V> source, K key, BiConsumer<K, V> consumer) {
        Assert.notNull(source);
        Assert.notNull(consumer);

        V value = source.get(key);
        if(value != null) {
            consumer.accept(key, value);
        }
    }
}
