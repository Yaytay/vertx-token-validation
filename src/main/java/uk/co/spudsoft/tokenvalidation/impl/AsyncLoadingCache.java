/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.co.spudsoft.tokenvalidation.impl;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableSet;
import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class backed by a Guava Cache that returns a Future for all elements whilst
 * still ensuring that the loader is only called once at a time per element.
 * @author njt
 * @param <K> The key type for the cache.
 * @param <V> The value type stored in the cache.
 */
public class AsyncLoadingCache<K, V> {
  
  @SuppressWarnings("constantname")
  private static final Logger logger = LoggerFactory.getLogger(AsyncLoadingCache.class);
 
  /**
   * Data class for items stored in the backing cache.
   */
  private class Data {
    private List<Promise<V>> initialPromises;
    private boolean completed;
    private boolean succeeded;
    private long expiry;
    private V result;

    Data() {
      this.initialPromises = new ArrayList<>();
      this.expiry = Long.MAX_VALUE;
    }    
    
    void update(boolean succeeded, V value) {
      this.initialPromises = new ArrayList<>();
      this.completed = true;
      this.succeeded = succeeded;
      if (succeeded) {
        this.expiry = getExpiry.apply(value);
        this.result = value;
      }
    }
  }
  
  private final Object lock = new Object();
  private final Cache<K, Data> backing = CacheBuilder.newBuilder().build();
  private final Function<V, Long> getExpiry;

  /**
   * Constructor.
   * @param getExpiry Function to extract the expiry time (in ms since epoch) from a V type.
   */
  @SuppressWarnings("unchecked")
  public AsyncLoadingCache(Function<V, Long> getExpiry) {
    this.getExpiry = getExpiry;
  }

  /**
   * Return true if the cache already contains a value for the provided key.
   * @param key the key to check.
   * @return true if the cache already contains a value for the provided key.
   */
  public boolean containsKey(K key) {
    return backing.asMap().containsKey(key);
  }

  /**
   * Associates {@code value} with {@code key} in this cache.
   * 
   * If the cache previously contained a value associated with {@code key}, the old value is replaced by {@code value}.
   * 
   * p>Prefer {@link #get(Object, Callable)} when using the conventional "if cached, return; otherwise create, cache and return" pattern.
   *
   * @param key the key to set.
   * @param value the value to set.
   */
  public void put(K key, V value) {
    Data data = new Data();
    data.update(true, value);
    backing.put(key, new Data());
  }
  
  /**
   * Get an item from the cache, returning a Future in case the item is not already there.
   * @param key The key for the item in the cache.
   * @param loader Callable that actually gets the value.
   * @return The value returned either by this Callable or some previous instance of it.
   */
  public Future<V> get(K key, Callable<Future<V>> loader) {
    Promise<V> promise;
    Data data;
    synchronized (lock) {
      data = backing.getIfPresent(key);
      if (data != null && (data.expiry > System.currentTimeMillis())) {
        if (data.completed) {
          if (data.succeeded) {
            return Future.succeededFuture(data.result);
          } else {
            // Previous request failed, so try again (don't cache failures)
            promise = createAndAddInitialPromise(data.initialPromises);
            data.completed = false;
          }
        } else {
          promise = createAndAddInitialPromise(data.initialPromises);
          return promise.future();
        }
      } else {
        data = new Data();
        promise = createAndAddInitialPromise(data.initialPromises);
        backing.put(key, data);
      }
    }
    Data finalData = data;
    try {
      loader.call().onComplete(ar -> handleAfterLoaderCall(ar, finalData));
    } catch (Throwable ex) {
      logger.error("Failed to call loader: ", ex);
      return Future.failedFuture(ex);
    }
    return promise.future();
  }

  /**
   * Get an immutable view of the keys currently in the backing map.
   * @return an immutable view of the keys currently in the backing map.
   */
  public Set<K> keySet() {
    return ImmutableSet.copyOf(backing.asMap().keySet());
  }
  
  private Promise<V> createAndAddInitialPromise(List<Promise<V>> initialPromises) {
    Promise<V> promise = Promise.promise();
    initialPromises.add(promise);
    return promise;
  }

  private void handleAfterLoaderCall(AsyncResult<V> asyncResult, Data data) {
    boolean succeeded = asyncResult.succeeded();
    V result = asyncResult.result();
    List<Promise<V>> initialPromises;
    synchronized (lock) {
      initialPromises = data.initialPromises;
      data.update(succeeded, result);
    }
    if (succeeded) {
      for (Promise<V> initialPromise : initialPromises) {
        initialPromise.complete(result);
      }
    } else {
      for (Promise<V> initialPromise : initialPromises) {
        initialPromise.fail(asyncResult.cause());
      }
    }
  }
}
