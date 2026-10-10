package com.lauriewired.ghidramcp.core;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * One page of a list result.
 */
public record Page<T>(List<T> items, int offset, int limit, int total, boolean hasMore) {

	public static final int MAX_LIMIT = 2000;

	public static int clampLimit(int limit) {
		return Math.max(1, Math.min(limit, MAX_LIMIT));
	}

	public static <T> Page<T> of(List<T> all, int offset, int limit) {
		Builder<T> builder = new Builder<>(offset, limit);
		for (T item : all) {
			builder.offer(() -> item);
		}
		return builder.build();
	}

	/**
	 * Counts every offered item but only materializes the ones inside the requested window.
	 */
	public static final class Builder<T> {
		private final int offset;
		private final int limit;
		private final List<T> items = new ArrayList<>();
		private int total;

		public Builder(int offset, int limit) {
			this.offset = Math.max(0, offset);
			this.limit = clampLimit(limit);
		}

		public void offer(Supplier<T> item) {
			if (total >= offset && items.size() < limit) {
				items.add(item.get());
			}
			total++;
		}

		public Page<T> build() {
			return new Page<>(items, offset, limit, total, offset + items.size() < total);
		}
	}
}
